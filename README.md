# ATT&CK Detections Collector
Collects a listing ot ATT&CK techniques, then discovers ESCU detections for the technique. Results may be saved as HTML or for use with ATT&CK Navigator.


## Installation

    pip3 install -r requirements.txt

## Usage


To display usage, simply run: `python3 adc.py -h`

    usage: adc.py [-h] [-e EXTRACT_IDS [EXTRACT_IDS ...]] [-t TECHNIQUE_IDS [TECHNIQUE_IDS ...]]
                  [-d DETECTIONS] [-o OUTFILE] [--as-navigator]
                  [--attack-domain {enterprise-attack,mobile-attack,pre-attack}] [--update-cache]

    optional arguments:
      -h, --help            show this help message and exit
      -e EXTRACT_IDS [EXTRACT_IDS ...], --extract-ids EXTRACT_IDS [EXTRACT_IDS ...]
                            Extract ATT&CK Techniques IDs from file or URL
      -t TECHNIQUE_IDS [TECHNIQUE_IDS ...], --technique-ids TECHNIQUE_IDS [TECHNIQUE_IDS ...]
                            ATT&CK Techniques IDs to find
      -d DETECTIONS, --detections DETECTIONS
                            Path to ESCU detections root
      -o OUTFILE, --outfile OUTFILE
                            Filename to save results to
      --as-navigator        Save results as ATT&CK Navigator instead of HTML table
      --attack-domain {enterprise-attack,mobile-attack,pre-attack}
                            ATT&CK Framework to leverage
      --update-cache        Update the locally cached ATT&CK database


### HTML Output

To query for specific techniques and save results to an HTML file: 

    python3 adc.py -t T1133 T1078 T1059.001 -o results.html


Or, to pull content from a URL and automagically extract techniques:

    python3 adc.py -e  https://www.splunk.com/en_us/blog/security/supernova-redux-with-a-generous-portion-of-masquerading.html \
        -o results.html

You will have an HTML table containing all detections identified.


### ATT&CK Navigator Output


To query for specific techniques and save results to an HTML file: 

    python3 adc.py -t T1133 T1078 T1059.001 -o results-navigator.json --as-navigator


Or, to pull content from a URL and automagically extract techniques:

    python3 adc.py -e  https://www.splunk.com/en_us/blog/security/supernova-redux-with-a-generous-portion-of-masquerading.html \
        -o results-navigator.json --as-navigator

#### ATT&CK Navigator Template Customizations

The output for ATT&CK Navigator may be customized by updating `attack-navigator-template.json`. This script requires a fully functional template that must includes the `techniques` object within the json.
