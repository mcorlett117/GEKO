# Use an official lightweight Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first to leverage Docker's layer caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY ./src ./src

# Declare a volume for the threat reports.
VOLUME ["/app/Threat-Report"]

# The command to run when the container starts.
# It will run your main script.
CMD [ "python", "./src/main.py" ]