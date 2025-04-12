

import PyPDF2
import pdfplumber
import fitz  # PyMuPDF
import pytesseract
import os
from pdf2image import convert_from_path
from flask import jsonify

import pandas as pd
from docx import Document  # Import Document from python-docx
class PdfReaderFactory(object):
    """
    
    """   

    def extract_text_pypdf2(self, pdf_path):
        """ Using PyPDF2 (simple text extraction): """
        with open(pdf_path, "rb") as file:
            reader = PyPDF2.PdfReader(file)
            text = ""
            for page in reader.pages:
                text += page.extract_text()
            return text
    
    #
    def extract_text_pdfplumber(self, pdf_path):
        """ Using pdfplumber (better for text and tables): """
        with pdfplumber.open(pdf_path) as pdf:
            text = ""
            for page in pdf.pages:
                text += page.extract_text()
            return text
    
    #
    def extract_tableswith_pdfplumber(self, pdf_path):
        """ Use pdfplumber for structured table extraction: """
        with pdfplumber.open(pdf_path) as pdf:
            tables = []
            for page in pdf.pages:
                tables.extend(page.extract_tables())
            return tables

    """tables = extract_tables("example.pdf")
    for table in tables:
        for row in table:
            print(row)"""
    
    #
    # Install:
    def extract_text_fitz(self, pdf_path):
        """Faster and more detailed than PyPDF2:"""
        doc = fitz.open(pdf_path)
        text = ""
        for page in doc:
            text += page.get_text()
        return text
    
    def extract_images_from_pdf(self, pdf_path):
        """   ----- """
       
        doc = fitz.open(pdf_path)

        for page_index, page in enumerate(doc):
            for img_index, img in enumerate(page.get_images(full=True)):
                xref = img[0]  # Get image reference
                base_image = doc.extract_image(xref)
                image_bytes = base_image["image"]
                
                with open(f"image_{page_index}_{img_index}.png", "wb") as f:
                    f.write(image_bytes)

    #
    def convert_pdf_to_csv(self, file_path, pdf_name):
        """"""
        data = []
        pdf_path=os.path.join(file_path, pdf_name)
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                table = page.extract_table()
                if table:
                    data.extend(table)

        df = pd.DataFrame(data)
        df.to_csv(pdf_path=os.path.join(file_path, "output.csv"), index=False)

    #
    def extract_text_ocr(self, file_path, pdf_name):
        """For image-based PDFs, use Tesseract OCR:"""
        pdf_path=os.path.join(file_path, pdf_name)
        images = convert_from_path(pdf_path)
        text = ""
        for i, image in enumerate(images):
            pdf_path=os.path.join(file_path, f"page_{i}.jpg")
            image.save(pdf_path, "JPEG")
            text += pytesseract.image_to_string(image)
            os.remove(pdf_path)  # Clean up images
        return text

    def convert_html_to_pdf(self, file_path, html_file):
        """Use pdfkit to convert HTML (rendered from markdown) to PDF:
        # Also install wkhtmltopdf: https://wkhtmltopdf.org/
        """
        # Convert markdown to HTML first (use a library like markdown2)
        #html_content = markdown2.markdown(optimized_cv)
        #pdfkit.from_string(html_content, "optimized_cv.pdf")
    

    def pdf_to_docx(pdf_path, docx_path):
        """Extract text and images, then rebuild the DOCX manually. 
            
            Limitations:
            No table/image extraction (requires additional code).

            Formatting (bold, italics) is lost.
        """
        try:
            doc = Document()
            pdf = fitz.open(pdf_path)

            for page in pdf:
                text = page.get_text()
                doc.add_paragraph(text)

            doc.save(docx_path)
            return True, docx_path
        except Exception as e:
            return False, str(e)