"""
Data Extraction & Secure Validation Program
Author: Junior Frontend Developer
Purpose: Extract structured data from raw text using regex with security validation

This program implements regex-based extraction for 8 data types:
1. Email addresses
2. URLs
3. Phone numbers
4. Credit card numbers
5. Time (12-hour and 24-hour formats)
6. HTML tags
7. Hashtags
8. Currency amounts

Security Considerations:
- Input validation to prevent injection attacks
- Detection of malicious patterns (SQL injection, XSS, path traversal)
- Masking of sensitive data in outputs
- Length limits to prevent DoS attacks
"""

import re
import json
from typing import Dict, List, Tuple


class DataExtractor:
    """
    Secure data extraction class with regex patterns and validation
    """
    
    # Maximum input length to prevent DoS attacks
    MAX_INPUT_LENGTH = 100000
    
    # Regex patterns for each data type
    PATTERNS = {
        # Email: Matches standard email formats with various TLDs
        # Supports dots, hyphens, underscores in local part
        # Pattern explanation:
        # - [a-zA-Z0-9._-]+ : Local part (before @)
        # - @ : At symbol
        # - [a-zA-Z0-9.-]+ : Domain name
        # - \.[a-zA-Z]{2,} : TLD (minimum 2 characters)
        'email': r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        
        # URL: Matches http/https URLs with optional ports and paths
        # Pattern explanation:
        # - https? : Protocol (http or https)
        # - :// : Protocol separator
        # - [\w.-]+ : Domain with subdomains
        # - (:\d+)? : Optional port number
        # - (/[^\s]*)? : Optional path and query parameters
        'url': r'https?://[\w.-]+(?::\d+)?(?:/[^\s]*)?',
        
        # Phone: Matches common US phone number formats
        # Supports: (123) 456-7890, 123-456-7890, 123.456.7890
        # Pattern explanation:
        # - (\(\d{3}\)|\d{3}) : Area code with or without parentheses
        # - [-.\s]? : Optional separator
        # - \d{3}[-.\s]?\d{4} : Remaining 7 digits with optional separator
        'phone': r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
        
        # Credit Card: Matches 16-digit cards with various separators
        # Supports spaces, hyphens, or no separator
        # Pattern explanation:
        # - \d{4} : First 4 digits
        # - [-\s]? : Optional separator (space or hyphen)
        # - Repeated for all 4 groups
        'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        
        # Time: Matches both 12-hour and 24-hour formats
        # Pattern explanation:
        # 24-hour: ([01]?[0-9]|2[0-3]):[0-5][0-9]
        # 12-hour: (1[0-2]|0?[1-9]):[0-5][0-9]\s?(AM|PM|am|pm)
        'time': r'\b(?:[01]?[0-9]|2[0-3]):[0-5][0-9](?:\s?(?:AM|PM|am|pm))?\b',
        
        # HTML Tags: Matches opening and closing HTML tags with attributes
        # Pattern explanation:
        # - </?[a-zA-Z][a-zA-Z0-9]* : Tag name (opening or closing)
        # - (?:\s+[^>]*)? : Optional attributes
        # - /?> : Tag closing (self-closing or regular)
        'html_tag': r'</?[a-zA-Z][a-zA-Z0-9]*(?:\s+[^>]*)?/?>',
        
        # Hashtags: Matches social media style hashtags
        # Pattern explanation:
        # - # : Hash symbol
        # - [a-zA-Z0-9_]+ : Alphanumeric characters and underscores
        # - Must not be preceded by alphanumeric character
        'hashtag': r'(?<![a-zA-Z0-9])#[a-zA-Z0-9_]+',
        
        # Currency: Matches dollar amounts with optional cents and commas
        # Pattern explanation:
        # - \$ : Dollar sign
        # - \d{1,3}(?:,\d{3})* : Whole dollars with optional comma separators
        # - (?:\.\d{2})? : Optional cents (exactly 2 digits)
        'currency': r'\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?'
    }
    
    # Malicious patterns to detect and reject
    MALICIOUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # XSS: Script tags
        r'javascript:',                 # XSS: JavaScript protocol
        r'on\w+\s*=\s*["\']',          # XSS: Event handlers with quotes
        r'(?:\'|\")\s*(?:;|--)',       # SQL injection: quotes followed by SQL delimiters
        r'\b(?:union|select|insert|update|delete|drop)\s+(?:all\s+)?(?:from|into|table)',  # SQL keywords in context
        r'\.\./\.\./|\.\.\%2[fF]',     # Path traversal attempts (multiple levels)
        r'\b(?:eval|exec|system|passthru|shell_exec)\s*\(',  # Code execution functions
        r'(?:file|ftp|data|expect)://',  # Dangerous protocols
    ]
    
    def __init__(self):
        """Initialize the data extractor with compiled patterns"""
        self.compiled_patterns = {
            key: re.compile(pattern, re.IGNORECASE if key in ['time', 'html_tag'] else 0)
            for key, pattern in self.PATTERNS.items()
        }
        
        self.compiled_malicious = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.MALICIOUS_PATTERNS
        ]
    
    def validate_input(self, text: str) -> Tuple[bool, str]:
        """
        Validate input text for security issues
        
        Args:
            text: Input text to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check length to prevent DoS
        if len(text) > self.MAX_INPUT_LENGTH:
            return False, f"Input exceeds maximum length of {self.MAX_INPUT_LENGTH} characters"
        
        # Check for malicious patterns
        for pattern in self.compiled_malicious:
            if pattern.search(text):
                return False, "Input contains potentially malicious content"
        
        return True, ""
    
    def mask_sensitive_data(self, data: str, data_type: str) -> str:
        """
        Mask sensitive information for safe output
        
        Args:
            data: The extracted data
            data_type: Type of data (e.g., 'credit_card', 'email')
            
        Returns:
            Masked version of the data
        """
        if data_type == 'credit_card':
            # Mask all but last 4 digits
            clean_card = re.sub(r'[-\s]', '', data)
            if len(clean_card) >= 4:
                return '*' * (len(clean_card) - 4) + clean_card[-4:]
        
        elif data_type == 'email':
            # Mask part of email local part
            if '@' in data:
                local, domain = data.split('@', 1)
                if len(local) > 2:
                    masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
                    return f"{masked_local}@{domain}"
        
        return data
    
    def extract_data(self, text: str, mask_sensitive: bool = True) -> Dict[str, List[str]]:
        """
        Extract all data types from input text
        
        Args:
            text: Input text to process
            mask_sensitive: Whether to mask sensitive data in output
            
        Returns:
            Dictionary with data types as keys and lists of matches as values
        """
        # Validate input first
        is_valid, error_msg = self.validate_input(text)
        if not is_valid:
            return {'error': [error_msg]}
        
        results = {}
        
        for data_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            
            # Remove duplicates while preserving order
            unique_matches = []
            seen = set()
            for match in matches:
                if match not in seen:
                    seen.add(match)
                    unique_matches.append(match)
            
            # Apply masking for sensitive data if requested
            if mask_sensitive and data_type in ['credit_card', 'email']:
                unique_matches = [
                    self.mask_sensitive_data(match, data_type) 
                    for match in unique_matches
                ]
            
            results[data_type] = unique_matches
        
        return results
    
    def format_output(self, results: Dict[str, List[str]]) -> str:
        """
        Format extraction results as readable text
        
        Args:
            results: Dictionary of extraction results
            
        Returns:
            Formatted string output
        """
        if 'error' in results:
            return f"ERROR: {results['error'][0]}"
        
        output = []
        output.append("=" * 60)
        output.append("DATA EXTRACTION RESULTS")
        output.append("=" * 60)
        
        # Define display names
        display_names = {
            'email': 'Email Addresses',
            'url': 'URLs',
            'phone': 'Phone Numbers',
            'credit_card': 'Credit Card Numbers',
            'time': 'Time Values',
            'html_tag': 'HTML Tags',
            'hashtag': 'Hashtags',
            'currency': 'Currency Amounts'
        }
        
        for data_type, matches in results.items():
            output.append(f"\n{display_names.get(data_type, data_type)}:")
            output.append("-" * 40)
            
            if matches:
                for idx, match in enumerate(matches, 1):
                    output.append(f"  {idx}. {match}")
            else:
                output.append("  No matches found")
        
        output.append("\n" + "=" * 60)
        return "\n".join(output)


def main():
    """
    Main function to demonstrate the data extractor
    """
    # Initialize extractor
    extractor = DataExtractor()
    
    # Read sample input
    try:
        with open('sample_input.txt', 'r', encoding='utf-8') as f:
            input_text = f.read()
    except FileNotFoundError:
        print("Error: sample_input.txt not found")
        return
    
    # Extract data
    print("Processing input text...\n")
    results = extractor.extract_data(input_text, mask_sensitive=True)
    
    # Display results
    print(extractor.format_output(results))
    
    # Save results to JSON file
    with open('extraction_results.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print("\nResults also saved to extraction_results.json")


if __name__ == "__main__":
    main()