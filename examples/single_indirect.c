int foo(){
	return 0;
} 

typedef int (*func_ptr)();

int main(){
	func_ptr f = foo; 
	return f();
}
