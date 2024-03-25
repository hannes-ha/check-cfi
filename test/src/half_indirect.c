typedef int (*func_ptr)();


int bar(){
	return 1;
} 

int foo(){
	func_ptr b = bar; 
	return b();
} 


int main(){
	func_ptr b = bar; 
	int y = b();

	int x = foo();

	return x + y;
}
