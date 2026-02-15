import os
import json
from pathlib import Path
from typing import Dict, List, Union, Optional, Any, Iterator, Tuple
import re
from datetime import datetime

#READTHIS:
#Getting the CVE data 
#git clone https://github.com/CVEProject/cvelistV5.git --depth 100

class JSONProcessor:
    def __init__(self, base_directory: str):
        """
        Initialize the JSON processor with a base directory.
        
        Args:
            base_directory (str): Path to the directory containing JSON files
        """
        self.base_directory = Path(base_directory)
        
    def get_json_files(self, recursive: bool = True) -> Iterator[Path]:
        """
        Generator that yields JSON file paths one at a time.
        
        Args:
            recursive (bool): Whether to search subdirectories recursively
            
        Yields:
            Path: JSON file path
        """
        if not self.base_directory.exists():
            print(f"Directory {self.base_directory} does not exist.")
            return
            
        # Get all JSON files
        if recursive:
            json_files = self.base_directory.rglob("*.json")
        else:
            json_files = self.base_directory.glob("*.json")
            
        for json_file in json_files:
            yield json_file
    
    def process_json_file(self, json_file: Path) -> Optional[dict]:
        """
        Load and return a single JSON file's content.
        
        Args:
            json_file (Path): Path to the JSON file
            
        Returns:
            Optional[dict]: JSON content or None if error
        """
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON in {json_file}: {e}")
            return None
        except Exception as e:
            print(f"Error loading {json_file}: {e}")
            return None
    
    def process_json_files_by_pattern(self, pattern: str = "*.json") -> Iterator[Tuple[Path, dict]]:
        """
        Generator that processes JSON files matching a specific pattern one at a time.
        
        Args:
            pattern (str): Glob pattern to match files
            
        Yields:
            Tuple[Path, dict]: File path and JSON content
        """
        for json_file in self.base_directory.rglob(pattern):
            if json_file.suffix.lower() == '.json':
                data = self.process_json_file(json_file)
                if data is not None:
                    yield json_file, data
    
    def get_file_count(self, recursive: bool = True) -> int:
        """
        Count the number of JSON files without loading them.
        
        Args:
            recursive (bool): Whether to count files recursively
            
        Returns:
            int: Number of JSON files
        """
        count = 0
        for _ in self.get_json_files(recursive):
            count += 1
        return count
    
    def get_json_file_info(self, json_file: Path) -> Dict[str, Any]:
        """
        Get information about a single JSON file.
        
        Args:
            json_file (Path): Path to the JSON file
            
        Returns:
            Dict[str, Any]: File information
        """
        if not json_file.exists():
            return {}
            
        stats = json_file.stat()
        relative_path = json_file.relative_to(self.base_directory)
        
        return {
            'relative_path': str(relative_path),
            'size_bytes': stats.st_size,
            'modified_time': stats.st_mtime,
            'full_path': str(json_file),
            'exists': json_file.exists()
        }


def filter_cve_data(cve_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter CVE JSON data to extract only important information.
    
    Args:
        cve_json (Dict[str, Any]): Raw CVE JSON data
        
    Returns:
        Dict[str, Any]: Filtered CVE data with only essential information
    """
    filtered_data = {}
    
    # Extract CVE ID and basic metadata
    cve_metadata = cve_json.get("cveMetadata", {})
    filtered_data["cve_id"] = cve_metadata.get("cveId", "Unknown")
    filtered_data["state"] = cve_metadata.get("state", "Unknown")
    filtered_data["date_published"] = cve_metadata.get("datePublished", "Unknown")
    filtered_data["date_updated"] = cve_metadata.get("dateUpdated", "Unknown")
    
    # Extract CNA (CVE Numbering Authority) data
    cna_data = cve_json.get("containers", {}).get("cna", {})
    
    # Extract title
    filtered_data["title"] = cna_data.get("title", "No title available")
    
    # Extract English descriptions and clean HTML
    descriptions = cna_data.get("descriptions", [])
    english_descriptions = []
    
    for desc in descriptions:
        if desc.get("lang") == "en":
            desc_value = desc.get("value", "")
            # Clean HTML tags from description
            clean_desc = re.sub(r'<[^>]+>', '', desc_value)
            # Clean extra whitespace
            clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
            if clean_desc:
                english_descriptions.append(clean_desc)
    
    filtered_data["description"] = english_descriptions[0] if english_descriptions else "No description available"
    
    # Extract severity and CVSS scores
    metrics = cna_data.get("metrics", [])
    severity_info = {}
    
    for metric in metrics:
        if "cvssV4_0" in metric:
            cvss4 = metric["cvssV4_0"]
            severity_info["cvss_v4"] = {
                "base_score": cvss4.get("baseScore", 0.0),
                "base_severity": cvss4.get("baseSeverity", "Unknown"),
                "vector_string": cvss4.get("vectorString", ""),
                "attack_vector": cvss4.get("attackVector", "Unknown"),
                "attack_complexity": cvss4.get("attackComplexity", "Unknown"),
                "privileges_required": cvss4.get("privilegesRequired", "Unknown"),
                "user_interaction": cvss4.get("userInteraction", "Unknown")
            }
        elif "cvssV3_1" in metric:
            cvss3 = metric["cvssV3_1"]
            severity_info["cvss_v3"] = {
                "base_score": cvss3.get("baseScore", 0.0),
                "base_severity": cvss3.get("baseSeverity", "Unknown"),
                "vector_string": cvss3.get("vectorString", ""),
                "attack_vector": cvss3.get("attackVector", "Unknown"),
                "attack_complexity": cvss3.get("attackComplexity", "Unknown"),
                "privileges_required": cvss3.get("privilegesRequired", "Unknown"),
                "user_interaction": cvss3.get("userInteraction", "Unknown")
            }
        elif "cvssV3_0" in metric:
            cvss3 = metric["cvssV3_0"]
            severity_info["cvss_v3"] = {
                "base_score": cvss3.get("baseScore", 0.0),
                "base_severity": cvss3.get("baseSeverity", "Unknown"),
                "vector_string": cvss3.get("vectorString", ""),
                "attack_vector": cvss3.get("attackVector", "Unknown"),
                "attack_complexity": cvss3.get("attackComplexity", "Unknown"),
                "privileges_required": cvss3.get("privilegesRequired", "Unknown"),
                "user_interaction": cvss3.get("userInteraction", "Unknown")
            }
    
    filtered_data["severity"] = severity_info
    
    # Extract CWE (Common Weakness Enumeration) information
    problem_types = cna_data.get("problemTypes", [])
    cwe_info = []
    
    for problem_type in problem_types:
        descriptions = problem_type.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en" or not desc.get("lang"):
                cwe_entry = {
                    "cwe_id": desc.get("cweId", "Unknown"),
                    "description": desc.get("description", "Unknown")
                }
                cwe_info.append(cwe_entry)
    
    filtered_data["weaknesses"] = cwe_info
    
    # Extract affected products/vendors
    affected = cna_data.get("affected", [])
    affected_products = []
    
    for item in affected:
        product_info = {
            "vendor": item.get("vendor", "Unknown"),
            "product": item.get("product", "Unknown"),
            "versions": []
        }
        
        versions = item.get("versions", [])
        for version in versions:
            version_info = {
                "version": version.get("version", "Unknown"),
                "status": version.get("status", "Unknown")
            }
            product_info["versions"].append(version_info)
        
        affected_products.append(product_info)
    
    filtered_data["affected_products"] = affected_products
    
    # Extract references (solutions, advisories, etc.)
    references = cna_data.get("references", [])
    reference_urls = []
    
    for ref in references:
        url = ref.get("url", "")
        if url:
            reference_urls.append(url)
    
    filtered_data["references"] = reference_urls
    
    # Extract source discovery method
    source = cna_data.get("source", {})
    filtered_data["discovery_method"] = source.get("discovery", "Unknown")
    
    # Add a summary of the most critical information
    filtered_data["summary"] = {
        "cve_id": filtered_data["cve_id"],
        "severity": _get_highest_severity(severity_info),
        "score": _get_highest_score(severity_info),
        "primary_weakness": cwe_info[0]["cwe_id"] if cwe_info else "Unknown",
        "affected_vendor": affected_products[0]["vendor"] if affected_products else "Unknown",
        "has_references": len(reference_urls) > 0
    }
    
    return filtered_data

def _get_highest_severity(severity_info: Dict) -> str:
    """Helper function to get the highest severity rating."""
    if "cvss_v4" in severity_info:
        return severity_info["cvss_v4"].get("base_severity", "Unknown")
    elif "cvss_v3" in severity_info:
        return severity_info["cvss_v3"].get("base_severity", "Unknown")
    return "Unknown"

def _get_highest_score(severity_info: Dict) -> float:
    """Helper function to get the highest CVSS score."""
    if "cvss_v4" in severity_info:
        return severity_info["cvss_v4"].get("base_score", 0.0)
    elif "cvss_v3" in severity_info:
        return severity_info["cvss_v3"].get("base_score", 0.0)
    return 0.0

def print_cve_summary(filtered_cve: Dict[str, Any]) -> None:
    """
    Print a human-readable summary of filtered CVE data.
    
    Args:
        filtered_cve (Dict[str, Any]): Filtered CVE data
    """
    print(f"CVE ID: {filtered_cve['cve_id']}")
    print(f"Title: {filtered_cve['title']}")
    print(f"Severity: {filtered_cve['summary']['severity']} (Score: {filtered_cve['summary']['score']})")
    print(f"Description: {filtered_cve['description']}")
    print(f"Primary Weakness: {filtered_cve['summary']['primary_weakness']}")
    print(f"Affected Vendor: {filtered_cve['summary']['affected_vendor']}")
    print(f"References Available: {'Yes' if filtered_cve['summary']['has_references'] else 'No'}")
    print(f"Published: {filtered_cve['date_published']}")
    print("-" * 80)

def save_cve_summary(filtered_cve: Dict[str, Any], output_dir: str = "filtered_cves_tree") -> None:
    """
    Save CVE summary to a file.
    
    Args:
        filtered_cve (Dict[str, Any]): Filtered CVE data
        output_dir (str): Output directory for saved files
    """
    # Create output directory if it doesn't exist
    CVEName = filtered_cve['cve_id']
    year = CVEName[4:8]
    year_dir = Path(output_dir) / year
    Path(output_dir).mkdir(exist_ok=True)
    Path(year_dir).mkdir(exist_ok=True)
    
    filename = f"{filtered_cve['cve_id']}.txt"
    filepath = Path(year_dir) / filename
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"CVE ID: {filtered_cve['cve_id']}\n")
            f.write(f"Title: {filtered_cve['title']}\n")
            f.write(f"Severity: {filtered_cve['summary']['severity']} (Score: {filtered_cve['summary']['score']})\n")
            f.write(f"Description: {filtered_cve['description']}\n")
            f.write(f"Primary Weakness: {filtered_cve['summary']['primary_weakness']}\n")
            f.write(f"Affected Vendor: {filtered_cve['summary']['affected_vendor']}\n")
            f.write(f"References Available: {'Yes' if filtered_cve['summary']['has_references'] else 'No'}\n")
            f.write(f"Published: {filtered_cve['date_published']}\n")
        print(f"Saved: {filename}")
    except Exception as e:
        print(f"Error saving {filename}: {e}")

def process_cves_efficiently(directory_path: str, output_dir: str = "filtered_cves", 
                           progress_interval: int = 100) -> None:
    """
    Process CVE JSON files one at a time to minimize memory usage.
    
    Args:
        directory_path (str): Path to directory containing CVE JSON files
        output_dir (str): Output directory for processed files
        progress_interval (int): How often to print progress updates
    """
    processor = JSONProcessor(directory_path)
    
    # Create output directory
    Path(output_dir).mkdir(exist_ok=True)
    
    # Get total count for progress tracking
    total_files = processor.get_file_count()
    print(f"Found {total_files} JSON files to process")
    print(f"Output directory: {output_dir}")
    print("-" * 50)
    
    processed_count = 0
    error_count = 0
    
    # Process files one at a time
    for json_file in processor.get_json_files():
        # Load and process single file
        cve_data = processor.process_json_file(json_file)
        
        if cve_data is not None:
            try:
                # Filter the CVE data
                filtered = filter_cve_data(cve_data)
                
                # Save the summary
                save_cve_summary(filtered, output_dir)
                
                processed_count += 1
                
                # Print progress
                if processed_count % progress_interval == 0:
                    print(f"Processed {processed_count}/{total_files} files...")
                    
            except Exception as e:
                print(f"Error processing {json_file}: {e}")
                error_count += 1
        else:
            error_count += 1
        
        # Clear the data from memory (Python's garbage collector will handle this,
        # but we can explicitly delete to be sure)
        del cve_data
    
    print(f"\nProcessing complete!")
    print(f"Successfully processed: {processed_count} files")
    print(f"Errors encountered: {error_count} files")
    print(f"Total files: {total_files}")

def main():
    """
    Main function with improved memory efficiency
    """
    # Get directory path from user
    directory_path = input("Enter the directory path containing JSON files: ").strip()
    
    if not directory_path:
        directory_path = "/home/lukas/AISweden/cvelistV5/cves"  # Default from original code
    
    # Get output directory
    output_dir = input("Enter output directory (default: filtered_cves_tree): ").strip()
    if not output_dir:
        output_dir = "filtered_cves_tree"
    
    print(f"\nProcessing JSON files from: {directory_path}")
    print(f"Output directory: {output_dir}")
    print("-" * 50)
    
    # Process files efficiently
    try:
        process_cves_efficiently(directory_path, output_dir)
    except KeyboardInterrupt:
        print("\nProcessing interrupted by user")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()