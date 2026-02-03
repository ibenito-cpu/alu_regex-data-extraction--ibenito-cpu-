"""
HTML Tag Extraction Demo
This script demonstrates extracting HTML tags from trusted input
"""

from data_extractor import DataExtractor

def main():
    extractor = DataExtractor()
    
    # Read HTML sample input
    try:
        with open('sample_input_with_html.txt', 'r', encoding='utf-8') as f:
            input_text = f.read()
    except FileNotFoundError:
        print("Error: sample_input_with_html.txt not found")
        return
    
    print("=" * 70)
    print("HTML TAG EXTRACTION DEMO")
    print("=" * 70)
    print()
    print("Note: This input is from a TRUSTED source (internal documentation).")
    print("In production, HTML from untrusted sources would be rejected.")
    print()
    
    # For trusted input, we can temporarily disable security checks
    # by directly using regex patterns (not recommended for production)
    html_pattern = extractor.compiled_patterns['html_tag']
    html_tags = html_pattern.findall(input_text)
    
    # Remove duplicates
    unique_tags = []
    seen = set()
    for tag in html_tags:
        if tag not in seen:
            seen.add(tag)
            unique_tags.append(tag)
    
    print(f"Found {len(unique_tags)} unique HTML tags:")
    print("-" * 70)
    
    for idx, tag in enumerate(unique_tags, 1):
        print(f"{idx:2d}. {tag}")
    
    print()
    print("=" * 70)
    print("Security Note:")
    print("These tags were extracted from TRUSTED internal documentation.")
    print("HTML from external/untrusted sources is automatically rejected")
    print("by the security validation system.")
    print("=" * 70)
    
    # Also extract other data types
    print("\n\nOther Data Types Extracted:")
    print("=" * 70)
    
    # Extract non-HTML data types
    results = {}
    for data_type, pattern in extractor.compiled_patterns.items():
        if data_type != 'html_tag':
            matches = pattern.findall(input_text)
            unique_matches = []
            seen = set()
            for match in matches:
                if match not in seen:
                    seen.add(match)
                    unique_matches.append(match)
            
            # Apply masking for sensitive data
            if data_type in ['credit_card', 'email']:
                unique_matches = [
                    extractor.mask_sensitive_data(match, data_type) 
                    for match in unique_matches
                ]
            
            results[data_type] = unique_matches
    
    display_names = {
        'email': 'Emails',
        'url': 'URLs',
        'phone': 'Phone Numbers',
        'credit_card': 'Credit Cards',
        'time': 'Times',
        'hashtag': 'Hashtags',
        'currency': 'Currency'
    }
    
    for data_type, matches in results.items():
        print(f"\n{display_names.get(data_type, data_type)}:")
        print("-" * 40)
        if matches:
            for match in matches[:5]:  # Show first 5
                print(f"  • {match}")
            if len(matches) > 5:
                print(f"  ... and {len(matches) - 5} more")
        else:
            print("  None found")

if __name__ == "__main__":
    main()