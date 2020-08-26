obj-m+=r00tkit.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build/ M=$(shell pwd) modules
clean:
	$(shell rm -f *.o *.order *.symvers *.mod*)
