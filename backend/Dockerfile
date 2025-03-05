# Use Python base image
FROM python:3.11

# Set the working directory
WORKDIR /app

# Copy the application files
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

# Expose the backend port (e.g., 5000)
EXPOSE 5000

# Run the Quart app
CMD ["python", "app.py"]
