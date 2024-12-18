#!/bin/bash

# Fixed commit message
commit_message="Some changes"

# Add all changes
git add *
if [ $? -eq 0 ]; then
    echo "Files added successfully."
else
    echo "Error adding files."
    exit 1
fi

# Commit with fixed message
git commit -m "$commit_message"
if [ $? -eq 0 ]; then
    echo "Changes committed successfully."
else
    echo "Error committing changes. Please check if there are staged changes."
    exit 1
fi

# Push to the 'main' branch
git push origin main
if [ $? -eq 0 ]; then
    echo "Changes pushed to the 'main' branch successfully."
else
    echo "Error pushing changes. Please check your connection or branch."
    exit 1
fi
