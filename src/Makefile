obj-m += dpatchdriver.o
dpatchdriver-objs := main.o dpatch.o
ccflags-y := -std=gnu99 -Wno-declaration-after-statement -Wframe-larger-than=1596

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean