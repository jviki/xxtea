all: compile-xxtea run-tests
compile-xxtea: xxtea
run-tests:

############

xxtea:
	$(MAKE) -C ..
	ln -f ../xxtea $@

clean:
	$(RM) xxtea
