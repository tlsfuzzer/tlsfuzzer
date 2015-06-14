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
	epydoc --check --fail-on-error -v tlsfuzzer
	coverage2 run --branch --source tlsfuzzer -m unittest discover -v
	coverage2 report -m
	coverage3 run --branch --source tlsfuzzer -m unittest discover -v
	coverage3 report -m
	coverage3 xml
	coverage3 html
	pylint --msg-template="{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}" tlsfuzzer > pylint_report.txt || :
	diff-quality --violations=pylint --fail-under=90 pylint_report.txt
	diff-cover --fail-under=90 coverage.xml
