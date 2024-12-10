from langchain.llms import Bedrock
from langchain.prompts import ChatPromptTemplate
from langchain.text_splitter import CharacterTextSplitter
import os
import sys
import re

# Retrieve AWS credentials and region from environment variables
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Error check for missing credentials
if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
    print("Error: AWS credentials not set.")
    sys.exit(1)

# Initialize Bedrock LLM with the correct region from environment variable
bedrock_llm = Bedrock(model_id="meta.llama3-2-11b-instruct-v1:0", region_name=AWS_REGION)

def split_code_with_langchain(content, chunk_size=3000, chunk_overlap=200):
    splitter = CharacterTextSplitter(
        separator="\n",  # Split by newlines
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
    )
    return splitter.split_text(content)

def analyze_code_chunk(chunk, chat_model):
    prompt_template = ChatPromptTemplate.from_template(
        """
        You are an application security and cloud security expert. if the chunk presented to you has code in it, analyze the following code chunk thoroughly for vulnerabilities according to the owasp code review guide. Do not just look for critical 
        issues. Identify issues of medium and low severity too. When you find the issues, enumerate them all and report them per the owasp code review guide standard. Start with the first finding and let the last finding
        be the end of the report. Do not write anything after the last vulnerability has been documented. Write the report in plain text and not markdown.

        If the chunk presented to you is a terraform file, analyze the following Terraform file and identify potential security issues. Review it according
        to best practices and guidelines such as the CIS Benchmarks, OWASP IaC Security principles, and cloud provider-specific security recommendations (e.g., AWS, Azure, GCP).

        {chunk}

        If it's a code file, provide:
        - A summary of each identified issue.
        - Detailed explanation of each issue.
        - Confidence (low, medium, high)
        - Potential severity (low, medium, high)
        - Suggestions for fixing the issue

        If it's a terraform file, provide:
        - A summary of identified issues.
        - Detailed explanation of each issue.
        - Confidence levels (low, medium, high).
        - Severity levels (low, medium, high).
        - Suggestions for fixing each issue.
        """
    )
    prompt = prompt_template.format(chunk=chunk)
    response = chat_model.invoke(prompt)
    return response.content

def analyze_large_file(file_content):
    chat = bedrock_llm  
    chunks = split_code_with_langchain(file_content)
    results = []
    for i, chunk in enumerate(chunks):
        print(f"Analyzing chunk {i + 1}/{len(chunks)}...")
        result = analyze_code_chunk(chunk, chat)
        results.append({"chunk": i + 1, "analysis": result})
    return results

def process_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            code_content = file.read()
            print(f"Analyzing {file_path}...")
            analysis = analyze_large_file(code_content)
            return {"file": file_path, "analysis": analysis}
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return {"file": file_path, "error": str(e)}

def scan_directory(directory="."):
    supported_extensions = {".py", ".js", ".java", ".cpp", ".c", ".rb", ".go", ".tf"}
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            _, extension = os.path.splitext(file)
            if extension in supported_extensions:
                result = process_file(file_path)
                results.append(result)
    return results

def process_results(results):
    high_severity_found = False

    for result in results:
        for finding in result.get("analysis", []):
            if re.search(r"(potential severity: high|severity: high)", finding.get("analysis", ""), re.IGNORECASE):
                high_severity_found = True

    if high_severity_found:
        print("Failing due to at least 1 high-severity vulnerability.")
        sys.exit(1)
    else:
        print("Success! No high-severity vulnerabilities found.")
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_code.py <path>")
        sys.exit(1)

    file_path = sys.argv[1]

    if os.path.isfile(file_path):
        result = process_file(file_path)
        print("\n--- Vulnerability Analysis Report ---\n")
        print(f"File: {result['file']}\n")
        for chunk_result in result.get("analysis", []):
            print(f"Chunk {chunk_result['chunk']}:\n")
            print(chunk_result.get("analysis", chunk_result.get("error")))
            print("\n" + "-" * 80 + "\n")
        process_results([result])

    elif os.path.isdir(file_path):
        results = scan_directory(file_path)
        for result in results:
            print("\n--- Vulnerability Analysis Report ---\n")
            print(f"File: {result['file']}\n")
            for chunk_result in result.get("analysis", []):
                print(f"Chunk {chunk_result['chunk']}:\n")
                print(chunk_result.get("analysis", chunk_result.get("error")))
                print("\n" + "-" * 80 + "\n")
        process_results(results)
    else:
        print("Invalid path. Please provide a valid file or directory.")