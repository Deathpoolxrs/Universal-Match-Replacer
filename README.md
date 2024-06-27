# Universal-Match-Replacer
The Universal Match Replacer is a Burp Suite extension designed to facilitate the dynamic replacement of regex patterns in HTTP requests, specifically for automated Burp scanners. 

# Usage
## Add the extension to Burp Suite's session handler to invoke the extension:
1. Go to the "Settings" tab in Burp Suite.
2. Navigate to the "Sessions" tab.
3. In "Session handling rules," click "Add."
4. Click "Add" under Rule Actions and select "Invoke Burp Extension."
5. Select the Universal Match Replacer.

## Adding Regex and Replace Text
1. Navigate to the "Universal Match Replacer" tab in Burp Suite.
2. Add regex and replacement fields by clicking the "Add Regex Field" button. Each field allows you to specify a regex pattern and the corresponding text to replace it with.
3. Once you have configured your patterns, click "Submit" to start the match and replace process.
