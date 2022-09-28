flake8 bin_handler.py
if [[ $? -eq 0 ]]; then
    echo
    echo "Code conforms."
    exit 0
else
    echo
    echo "Code does not conform---CI fails."
    exit 1
fi