#!/bin/bash
# Download dependencies script for network-suite

set -e

echo "Creating static directories..."
mkdir -p static/{css,js,fonts}

echo "Downloading Bootstrap CSS..."
curl -o static/css/bootstrap.min.css "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"

echo "Downloading Bootstrap JavaScript..."
curl -o static/js/bootstrap.bundle.min.js "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"

echo "Downloading Bootstrap Icons CSS..."
curl -o static/css/bootstrap-icons.css "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css"

echo "Downloading Bootstrap Icons fonts..."
curl -L -o /tmp/bootstrap-icons.zip "https://github.com/twbs/icons/releases/download/v1.11.1/bootstrap-icons-1.11.1.zip"
unzip -j /tmp/bootstrap-icons.zip "bootstrap-icons-1.11.1/fonts/bootstrap-icons.woff2" -d static/fonts/
unzip -j /tmp/bootstrap-icons.zip "bootstrap-icons-1.11.1/fonts/bootstrap-icons.woff" -d static/fonts/
rm /tmp/bootstrap-icons.zip

echo "Updating Bootstrap Icons CSS to use local fonts..."
sed -i.bak 's|url("./fonts/|url("../fonts/|g' static/css/bootstrap-icons.css
rm static/css/bootstrap-icons.css.bak

echo "Dependencies downloaded successfully!"
echo "The following files were created:"
find static -type f | sort
