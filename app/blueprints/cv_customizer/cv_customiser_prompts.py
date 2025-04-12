
class CvPrompts:
    
    def get(self,*,job_description, cv_content, id=0):

        context_01=""" Act as a professional recruiter and CV 
                    specialist with expertise in [industry, e.g., tech, healthcare, engineering]. 
                    Your task is to optimize my existing CV to precisely match the 
                    requirements of the following job description:  """
        
        context_02 =""" Act as a professional recruiter and CV specialist. 
        Optimize the following CV to match the job requirements listed below."""

        cv_optimization_prompt = f"""
            {context_01}
        
        **Job Description**:
        {job_description}

        rrent CV Content**:
        {cv_content}

        **Instructions**:
        1. Use ATS-friendly keywords from the job description.
        2. Quantify achievements with metrics (e.g., "Increased sales by 30%").
        3. Align skills and experience with the job's core requirements.
        4. To create the optimised CV follow the required structure: 
        4.1. Add an Header with the owner's name, address, phone contact if exists, email
        contact if exists, and a URL/link of the linkdin or github if exists.
        4.2 Add a Summary section explaining the owner social and hard skills to cativate atention.
        4.3 Add the Social skills section only if exists in the original CV.
        - Add a Core skills section
        - Add a Professional Experience section
        - Add the Education section 
        - Add the Certifications section only if exists in the original CV.
        - Add the Languages section
        - Add the Portfolio section only if exists in the original CV.
        5. Return only a structured JSON object with the optimized CV file content containing: 
        5.1. An HTML PAGE/DOCX-friendly plain text format including some css stylizations
        5.1.1 Return the optimized CV as **clean, UTF-8 encoded HTML**:
        - Do **NOT** include escape characters like `\n`, `\t`, or `\r`.
        - The HTML must be **properly formatted** and ready to be displayed in a browser.
        - Ensure that special characters (like accents and symbols) are correctly encoded in UTF-8.
        - Do **NOT** include unnecessary escape sequences (`\n`, `\\`, etc.).
        
        5.2. The CV optimised content in plain text with ATS-friendly formatted.
        6. Use the following keys for the json object elements: cv_in_html_format, cv_in_docx_format, cv_in_plain_text_format
        7. Add a "Changes Summary" section explaining key optimizations.
        """

        """
        5.2. Return the optimized CV in a **properly encoded Base64 DOCX file**.
        - The Base64 string must be **fully formed** and ready for decoding.
        - Do **NOT** return placeholders like "<base64_encoded_docx_content>". 
        - Ensure the output is valid and can be decoded directly into a downloadable file.
        """
        #5. Return the optimized CV in [HTML/DOCX-friendly plain text] format.
        #4. Return the optimized CV in markdown format.
        #

        match id:
            case 1:
                return cv_optimization_prompt
            case 2:
                return ""
        return "No prompt has found"
    
    # 
    def get_refined_prompt(self,*,job_description, cv_content):
        return f"""
            Act as a professional recruiter and CV specialist with expertise in [industry, e.g., tech, healthcare, engineering]. Your task is to optimize my existing CV to align perfectly with the job description provided.

            Instructions:

            1. Analyze & Optimize:

            1.1. Extract ATS-friendly keywords from the job description and integrate them into the CV.
            1.2. Ensure the CV aligns with the job’s core skills and experience requirements.
            1.3. Quantify achievements with metrics (e.g., “Increased sales by 30%”).
            
            2. Formatting & Output:

            2.1. Provide the optimized CV in two formats:
            2.2.1. Plain text (HTML/DOCX-friendly)
            2.2.2. A downloadable .DOCX file with ATS-compliant formatting.
            2.2. Include a "Changes Summary" section explaining key modifications and improvements.
            
            3. Input Data:
            3.1. Job Description:
            [```{job_description} ```] 
            3.2. Current CV Content:
            [```{cv_content}```]              
            
            4. Return the optimized CV strictly in the requested formats while ensuring readability, 
            relevance, and ATS compliance.
        """