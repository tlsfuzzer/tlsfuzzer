.PHONY : default
default:
	@echo "To install run \"./setup.py install\" or \"make install\""

clean:
	rm -f *.pyc */*.pyc
	rm -rf */__pycache__/

.PHONY : install
install:
	./setup.py install

test:
	python2 -m unittest discover -v
	python3 -m unittest discover -v
