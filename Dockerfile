# Use a lightweight Python image as the base
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and the application files to the container
COPY requirements.txt requirements.txt
COPY . .

# Install the required Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the Flask port (default is 5000)
EXPOSE 5000

# Set the command to run the Flask app
CMD ["python", "CLboth.py"]