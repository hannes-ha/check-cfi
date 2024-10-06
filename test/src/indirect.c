int foo(){
	return 0;
} 

int bar(){
	return 1;
} 

typedef int (*func_ptr)();

int main(){
	func_ptr f = foo; 
	func_ptr b = bar; 

	int x = f(); 
	int y = b();

	return x + y;
}
