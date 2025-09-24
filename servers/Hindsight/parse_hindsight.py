import pandas as pd
import re
import os

def parse_hindsight_output(input_path, output_path):
    """Parses the text output of the Hindsight analysis and creates a CSV timeline."""
    print(f"Parsing Hindsight output from: {input_path}")
    with open(input_path, 'r') as f:
        content = f.read()

    # This is a simplified parser. A real implementation would parse the JSONL directly.
    # For now, we'll extract URLs as a proof of concept.
    urls = re.findall(r'https?://[\S]+', content)
    
    if not urls:
        print("No URLs found in the Hindsight output.")
        return

    # Create a DataFrame suitable for Timesketch
    df = pd.DataFrame({
        'datetime': pd.to_datetime('today').strftime('%Y-%m-%d %H:%M:%S'),
        'timestamp_desc': 'Hindsight Analysis Event',
        'message': [f'URL visited: {url}' for url in urls]
    })

    print(f"Saving parsed data to CSV: {output_path}")
    df.to_csv(output_path, index=False)
    print("Parsing and conversion successful.")

if __name__ == "__main__":
    # Make paths relative to this script's location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(script_dir, "hindsight_output.txt")
    output_file = os.path.join(script_dir, "hindsight_timeline.csv")
    parse_hindsight_output(input_file, output_file)
