cd src
make

find . -name "*.o" -type f -delete
find . -name "*.cmd" -type f -delete
find . -name "*.mod" -type f -delete
find . -name "*.o.d" -type f -delete
find . -name "*.mod.o" -type f -delete
find . -name "*.mod.c" -type f -delete
find . -name "*.order" -type f -delete 
find . -name "*.symvers" -type f -delete

mv dpatchdriver.ko ..
cd ..