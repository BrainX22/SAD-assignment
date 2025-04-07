import React, { useState } from 'react';
import { 
  Box, 
  TextField, 
  Button, 
  Checkbox,
  FormControlLabel,
  Paper, 
  Typography,
  CircularProgress,
  Tabs,
  Tab,
  LinearProgress,
  Container,
  FormControl,
  InputLabel,
  Select,
  MenuItem
} from '@mui/material';
import axios from 'axios';

const Scanner = () => {
  const [tab, setTab] = useState(0);
  const [repoUrl, setRepoUrl] = useState('');
  const [code, setCode] = useState('');
  const [checkDependencies, setCheckDependencies] = useState(true);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [scanId, setScanId] = useState(null);
  const [language, setLanguage] = useState('python');

  const handleTabChange = (event, newValue) => {
    setTab(newValue);
    setResults(null);
    setError(null);
  };

  const handleLanguageChange = (event) => {
    setLanguage(event.target.value);
  };

  const handleScan = async () => {
    try {
      setLoading(true);
      setError(null);
      setResults(null);
      setScanProgress(0);
      setScanStatus('Initializing scan...');

      const response = await axios.post('/api/scan', {
        repo_url: tab === 0 ? repoUrl : null,
        code: tab === 1 ? code : null,
        check_dependencies: checkDependencies,
        language: language
      });

      if (response.data && response.data.scan_id) {
        setScanId(response.data.scan_id);
        pollScanResults(response.data.scan_id);
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error) {
      setError(error.response?.data?.error || 'An error occurred while scanning');
      setLoading(false);
    }
  };

  const pollScanResults = async (id) => {
    try {
      const response = await axios.get(`/api/scan/${id}`);
      const data = response.data;

      setScanProgress(data.progress || 0);
      setScanStatus(data.message || '');

      if (data.status === 'completed') {
        setResults(data.results);
        setLoading(false);
      } else if (data.status === 'error') {
        setError(data.message || 'An error occurred during scanning');
        setLoading(false);
      } else {
        // Continue polling
        setTimeout(() => pollScanResults(id), 1000);
      }
    } catch (error) {
      setError(error.response?.data?.error || 'An error occurred while checking scan status');
      setLoading(false);
    }
  };

  const renderResults = () => {
    if (!results) return null;

    return (
      <Paper elevation={3} sx={{ padding: 3, mt: 3 }}>
        <Typography variant="h6" gutterBottom>
          Results
        </Typography>
        
        {results.code_analysis && results.code_analysis.length > 0 ? (
          <>
            <Typography variant="subtitle1" gutterBottom>
              Code Analysis:
            </Typography>
            {results.code_analysis.map((result, index) => {
              // Extract filename from the full path
              const fileName = result.file.split('\\').pop();
              
              // Check if there are vulnerabilities in static analysis
              const hasVulnerabilities = result.static_analysis && 
                                        result.static_analysis.vulnerabilities && 
                                        result.static_analysis.vulnerabilities.length > 0;
              
              return (
                <Box key={index} sx={{ mb: 3, border: '1px solid #e0e0e0', borderRadius: 1, p: 2 }}>
                  <Typography variant="subtitle2" color="primary" gutterBottom>
                    File: {fileName}
                  </Typography>
                  
                  {hasVulnerabilities ? (
                    <Box sx={{ ml: 2 }}>
                      <Typography variant="body2" color="error" gutterBottom>
                        Vulnerabilities found:
                      </Typography>
                      {result.static_analysis.vulnerabilities.map((vuln, vIndex) => (
                        <Box key={vIndex} sx={{ ml: 2, mb: 1 }}>
                          <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                            {vuln.severity} - {vuln.description}
                          </Typography>
                          {vuln.line_numbers && vuln.line_numbers.length > 0 ? (
                            <Typography variant="body2" color="text.secondary">
                              Line(s): {vuln.line_numbers.join(', ')}
                            </Typography>
                          ) : vuln.line_number ? (
                            <Typography variant="body2" color="text.secondary">
                              Line: {vuln.line_number}
                            </Typography>
                          ) : null}
                        </Box>
                      ))}
                    </Box>
                  ) : (
                    <Typography variant="body2" color="success.main">
                      No vulnerabilities detected in this file.
                    </Typography>
                  )}
                  
                  {result.ai_analysis && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        AI Analysis:
                      </Typography>
                      <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
                        {result.ai_analysis}
                      </Typography>
                    </Box>
                  )}
                </Box>
              );
            })}
          </>
        ) : (
          <Typography variant="body1">No code analysis results available.</Typography>
        )}

        {tab === 0 && results.dependency_vulnerabilities && 
         results.dependency_vulnerabilities.length > 0 && (
          <>
            <Typography variant="subtitle1" gutterBottom sx={{ mt: 3 }}>
              Dependency Vulnerabilities:
            </Typography>
            {results.dependency_vulnerabilities.map((vuln, index) => (
              <Box key={index} sx={{ mb: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  Package: {vuln.package} (v{vuln.version})
                </Typography>
                {vuln.vulnerabilities?.map((v, i) => (
                  <Box key={i} sx={{ ml: 2 }}>
                    <Typography variant="body2">
                      CVE: {v.cve_id} (Severity: {v.severity})
                    </Typography>
                    <Typography variant="body2">
                      {v.description}
                    </Typography>
                  </Box>
                ))}
              </Box>
            ))}
          </>
        )}
        
        {results.summary && (
          <Box sx={{ mt: 3, p: 2, bgcolor: '#f5f5f5', borderRadius: 1 }}>
            <Typography variant="subtitle1" gutterBottom>
              Summary:
            </Typography>
            <Typography variant="body2">
              Total Files Analyzed: {results.summary.total_files_analyzed}
            </Typography>
            <Typography variant="body2">
              Total Vulnerabilities: {results.summary.total_vulnerabilities}
            </Typography>
            <Typography variant="body2" color="error">
              Critical Vulnerabilities: {results.summary.critical_vulnerabilities}
            </Typography>
            <Typography variant="body2" color="warning.main">
              High Severity Issues: {results.summary.high_vulnerabilities}
            </Typography>
            <Typography variant="body2" color="info.main">
              Medium Severity Issues: {results.summary.medium_vulnerabilities}
            </Typography>
            <Typography variant="body2" color="success.main">
              Low Severity Issues: {results.summary.low_vulnerabilities}
            </Typography>
          </Box>
        )}
      </Paper>
    );
  };

  const renderProgress = () => {
    if (!loading) return null;

    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          {scanStatus}
        </Typography>
        <LinearProgress variant="determinate" value={scanProgress} />
        <Typography variant="body2" color="text.secondary" align="right" sx={{ mt: 1 }}>
          {scanProgress}%
        </Typography>
      </Box>
    );
  };

  return (
    <Container maxWidth="md">
      <Paper elevation={3} sx={{ padding: 3, mt: 4 }}>
        <Typography variant="h5" gutterBottom>
          Code Security Scanner
        </Typography>

        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
          <Tabs value={tab} onChange={handleTabChange}>
            <Tab label="GitHub Repository" />
            <Tab label="Code Input" />
          </Tabs>
        </Box>

        {tab === 0 ? (
          <TextField
            fullWidth
            label="GitHub Repository URL"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            margin="normal"
            placeholder="https://github.com/username/repository"
          />
        ) : (
          <TextField
            fullWidth
            label="Code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            margin="normal"
            multiline
            rows={10}
            placeholder="Paste your code here..."
          />
        )}

        <FormControl fullWidth margin="normal">
          <InputLabel>Language</InputLabel>
          <Select
            value={language}
            onChange={handleLanguageChange}
            label="Language"
          >
            <MenuItem value="python">Python</MenuItem>
            <MenuItem value="javascript">JavaScript</MenuItem>
          </Select>
        </FormControl>

        <FormControlLabel
          control={
            <Checkbox
              checked={checkDependencies}
              onChange={(e) => setCheckDependencies(e.target.checked)}
            />
          }
          label="Check Dependencies"
        />

        <Button
          variant="contained"
          color="primary"
          onClick={handleScan}
          disabled={loading || (tab === 0 ? !repoUrl : !code)}
          sx={{ mt: 2 }}
        >
          {loading ? <CircularProgress size={24} /> : 'Scan'}
        </Button>

        {error && (
          <Typography color="error" sx={{ mt: 2 }}>
            {error}
          </Typography>
        )}
      </Paper>

      {renderProgress()}

      {renderResults()}
    </Container>
  );
};

export default Scanner;