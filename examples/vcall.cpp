struct First {
	virtual int foo(){
		return 1;
	};
};

struct Second: First {
	virtual int foo(){
		return 2;
	};
};

struct Third : Second {
	virtual int foo(){
		return 3;
	};
};

int main(){
	Second second;
	First& first_pointer_to_second = second;
	return  first_pointer_to_second.foo();  
}



