#!/bin/bash
# Fix all files with s.results references

for file in admin_panels.go api_docs.go backups.go comments.go directory_listing.go emails.go fingerprinting.go sourcemaps.go; do
    if [ -f "$file" ]; then
        echo "Fixing $file..."
        # Replace s.results with s.addFinding pattern
        sed -i 's/s\.results = append(s\.results, \(.*\))/s.addFinding(\1)/' "$file"
    fi
done
