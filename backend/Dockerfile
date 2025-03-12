# Use Python 3.11 as the base image
FROM python:3.11

# Set the working directory inside the container
WORKDIR /app

# Copy application files
COPY . /app

# Upgrade pip and install dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables if needed
ENV PYTHONUNBUFFERED=1

# Expose backend port
EXPOSE 5000

# Run the Quart app
CMD ["python", "app.py"]
