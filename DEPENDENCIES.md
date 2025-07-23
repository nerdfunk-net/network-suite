# Local Dependencies Setup

This document explains how the network-suite application has been configured to work with local dependencies instead of external CDNs, making it suitable for isolated Docker containers.

## Changes Made

### 1. Downloaded Dependencies
The following external dependencies have been downloaded and stored locally:

- **Bootstrap CSS** (v5.3.2): `static/css/bootstrap.min.css`
- **Bootstrap JavaScript** (v5.3.2): `static/js/bootstrap.bundle.min.js`
- **Bootstrap Icons CSS** (v1.11.1): `static/css/bootstrap-icons.css`
- **Bootstrap Icons Fonts** (v1.11.1): 
  - `static/fonts/bootstrap-icons.woff2`
  - `static/fonts/bootstrap-icons.woff`

### 2. Template Updates
The `templates/base.html` file has been updated to reference local files instead of CDN URLs:

**Before:**
```html
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-...">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-..."></script>
```

**After:**
```html
<link href="{{ url_for('static', filename='css/bootstrap.min.css') }}" rel="stylesheet">
<link rel="stylesheet" href="{{ url_for('static', filename='css/bootstrap-icons.css') }}">
<script src="{{ url_for('static', filename='js/bootstrap.bundle.min.js') }}"></script>
```

### 3. Font Path Fixes
The Bootstrap Icons CSS file has been updated to reference the correct local font paths:

**Before:**
```css
src: url("./fonts/bootstrap-icons.woff2?...") format("woff2"),
     url("./fonts/bootstrap-icons.woff?...") format("woff");
```

**After:**
```css
src: url("../fonts/bootstrap-icons.woff2?...") format("woff2"),
     url("../fonts/bootstrap-icons.woff?...") format("woff");
```

### 4. Docker Configuration
- Added `.dockerignore` file to exclude development files from the Docker build context
- The existing Dockerfile already copies all files, so no changes were needed

## Directory Structure

```
static/
├── css/
│   ├── bootstrap.min.css
│   └── bootstrap-icons.css
├── js/
│   └── bootstrap.bundle.min.js
└── fonts/
    ├── bootstrap-icons.woff
    └── bootstrap-icons.woff2
```

## Benefits

1. **Offline Operation**: The application can now run completely offline without internet access
2. **Reliability**: No dependency on external CDNs that might be unavailable
3. **Security**: No external requests that could be blocked by firewalls
4. **Performance**: Reduced latency as files are served locally
5. **Version Control**: Exact versions of dependencies are locked and version-controlled

## Re-downloading Dependencies

If you need to re-download the dependencies (e.g., for updates), use the provided script:

```bash
./download-dependencies.sh
```

This script will:
1. Create the necessary directories
2. Download all required files
3. Fix the font paths in the Bootstrap Icons CSS
4. List all downloaded files

## Docker Usage

The application can now be built and run in a completely isolated Docker container:

```bash
# Build the image
docker build -t network-suite .

# Run the container
docker run -p 5003:5003 network-suite
```

The static files will be automatically included in the Docker image and served by Flask.
