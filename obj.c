const char *get_hello(void)
{
    return "Hello, world!";
}

static int var = 5;

int get_var()
{
    return var;
}

void set_var(int num)
{
    var = num;
}

int add5(int num) {
    return num + 5;
}

int add10(int num) {
    num = add5(num);
    return add5(num);
}
