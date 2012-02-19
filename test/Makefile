all: compile-xxtea run-tests
compile-xxtea: xxtea
run-tests: test-seq

############

xxtea:
	$(MAKE) -C ..
	ln -f ../xxtea $@

test-seq:
	./xxtea -c -i seq.open -o seq.crypt.test -k key.txt
	diff seq.crypt.test seq.crypt
	./xxtea -d -i seq.crypt.test -o seq.open.test -k key.txt
	diff seq.open.test seq.open

clean:
	$(RM) xxtea
	$(RM) seq.open.test seq.crypt.test
