setup: requirements.txt
	pip install -r requirements.txt
	sudo apt-get install valgrind
clean:
	rm -rf __pycache__