# CTF Challenge Writeup: Includes

## Challenge Overview
**Title:** Includes  
**Category:** Web Exploitation  
**Difficulty:** Easy  
**Flag:** `picoCTF{1nclu51v17y_1of2_f7w_2of2_b8f4b022}`  

## Solution Summary
The challenge presented a webpage with a functional button that displayed an alert. The flag was discovered by examining the page's external resources.

## Methodology
1. **Initial reconnaissance** revealed a button labeled "say hello"
2. **Page source analysis** identified two linked files: `styles.css` and `script.js`
3. **Resource examination** located flag fragments in comments within both files
4. **Data reconstruction** combined the fragments to obtain the complete flag

## Technical Details
- **Vulnerability:** Information disclosure in client-side resources
- **Files examined:** 
  - `styles.css`: Contained `/* picoCTF{1nclu51v17y_1of2_ */`
  - `script.js`: Contained `// f7w_2of2_b8f4b022}`
- **Tools used:** Web browser, view source functionality

## Time to Solve
Approximately 5 minutes from initial access to flag capture.

**Solution validated and confirmed.**
