#include <iostream>
#include <string>
#include <bitset>
#include <time.h>
#include <stdint.h>
#include <sys/mman.h>   // Для mprotect
#include <unistd.h>     // Для sysconf
#include <cstdint>      // Для uintptr_t
#include <cerrno>       // Для errno
#include <cstring>      // Для strerror
#include <cstdlib>  // для rand() и srand()
#include <ctime>    // для time()
#include <vector>
#include <functional>
#include <fstream>
unsigned long GetAddrantiStepTraceCMP_and_CheckIntegrity();

bool make_memory_writable(unsigned int address, size_t size) {
    // Проверка: адрес не должен быть нулевым
    if (address == 0) {
        std::cerr << "Ошибка: нулевой адрес" << std::endl;
        return false;
    }

    // Получаем размер страницы памяти (обычно 4096 байт)
    size_t page_size = sysconf(_SC_PAGESIZE);

    // Приводим адрес к uintptr_t для арифметики
    uintptr_t addr = static_cast<uintptr_t>(address);

    // Выравниваем начальный адрес вниз до границы страницы
    uintptr_t page_start = addr & ~(page_size - 1);

    // Вычисляем конец области и округляем вверх до границы страницы
    uintptr_t end = addr + size;
    uintptr_t page_end = (end + page_size - 1) & ~(page_size - 1);

    // Общий размер изменяемой области (в байтах)
    size_t total_size = page_end - page_start;

    // Изменяем права доступа: читать, писать, выполнять
    if (mprotect(reinterpret_cast<void*>(page_start), total_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        std::cerr << "Ошибка mprotect: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

int password_to_hash(const std::string& pass){
int hash=0;
for (char c: pass){
    hash+=(hash<<5)^c;
}
return hash;
}

int GetCPUID(int eaxvalue){
    int result(0);
    asm volatile (
        "cpuid\n"
        :"=a" (result)
        : "a"(eaxvalue)      
        : "memory" 

    );
    return result;
}

int encryptGetCPUID(int eaxvalue){
    int result;
    //decrypted
    // asm volatile(
    //      ".byte 0x89, 0x7d, 0xec\n"
    //      ".byte 0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00\n"
    //      ".byte 0x8b, 0x45, 0xec\n"
    //      ".byte 0x0f, 0xa2\n"
    //      ".byte 0x89, 0x45, 0xfc \n"
    //      ".byte 0x8b, 0x45, 0xfc \n"
    //     : "=a" (result)  
    //     : "a" (eaxvalue) 
    //     : "ebx", "ecx", "edx", "memory" 
    // );

    //encrypted
    asm volatile(
        ".byte 0xd5, 0x75, 0xf8, 0xc3, 0xb7, 0x79, 0x99, 0x99, 0x99, 0x99, 0xe5, 0xb7, 0xf8, 0x06, 0xaa, 0xd5, 0xb7, 0x79, 0xe5, 0xb7, 0x79, 0xd5, 0xb7, 0x39, 0xe5, 0xb7, 0x39, 0xdf, 0xe5, 0x74, 0x59\n"
        :"=a" (result)
        :"a" (eaxvalue) 
        :"ebx", "ecx", "edx", "memory" 
    );
    return result;
}
unsigned long GetAddrEncrpyptdata(){
    int (*func_ptr)(int) = encryptGetCPUID;
    uintptr_t addr = (uintptr_t)func_ptr;
   // std::cout<<(unsigned long)addr;
    unsigned long int_addr=(unsigned long) addr + 11; //11 offset от функции
    return int_addr;
}

void encrypt(){
    unsigned long int_addr=GetAddrEncrpyptdata();
  //  std::cout<<"\n"<<int_addr<<"\n";
    int size=31;
    //offset 11 size 31
    make_memory_writable(int_addr,size);

    asm volatile(
        "next_byte_encrypt:\n"
        "sub byte ptr[eax],14\n"
        "rol byte ptr[eax],3\n"
        "xor byte ptr[eax],14\n"
        "inc eax\n"
        "loop next_byte_encrypt\n"
        :
        : "a" (int_addr), "c" (size) 
        : "memory" 
    );
}
void decrypt(){
    unsigned long int_addr=GetAddrEncrpyptdata();
   // std::cout<<"\n"<<int_addr<<"\n";
    int size=31;
    //offset 5 size 37
    make_memory_writable(int_addr,size);

    asm volatile(
        "next_byte_decrypt:\n"
        "xor byte ptr[eax],14\n"
        "ror byte ptr[eax],3\n"
        "add byte ptr[eax],14\n"
        "inc eax\n"
        "loop next_byte_decrypt\n"
        :
        : "a" (int_addr), "c" (size) 
        : "memory" 
    );
}
bool obfus_cmp(int a,int b){

try{
        //std::cout<<"\n\n"<<(hash_pass^true_pass);
        float res=(a^b);
        if (res == 0) {
        throw std::runtime_error("Division by zero!");  // Кидаем исключение вручную
    }
        return false;
        
    }catch(const std::exception& e){
        return true;
    }
}

long long GetTickCountLinux() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts); 
    return (long long)ts.tv_sec * 1000 + (long long)ts.tv_nsec / 1000000;
}
bool antiStepTraceCMP_and_CheckIntegrity(int hash_pass,int true_pass){
    //!!!!! только 32 битный режим 'gcc -m32'
//     asm goto (
// 	"push ss\n"    // сохраняем значение сегментного регистра SS в стеке
// 	"pop ss\n"     // записываем в регистр SS ранее сохраненное значение (перезаписываем SS)
// 	"pushfd\n"     // команда будет выполнена без останова из-за потери 
// 	"pop eax\n"    // из стека сохраненное значение регистра флагов помещаем в регистр eax
// 	"test ah, 1\n" // проверяем значение трассировочного флага (накладываем маск             
// 	"jz %l[no_step_trace]\n"
//     :
//     :
//     :
//     :no_step_trace
// );
// printf("Step-Trace is detected");
//     no_step_trace:
//offset 66
//size 14
unsigned int addr=GetAddrantiStepTraceCMP_and_CheckIntegrity();
int size=14;    
asm goto(
//      "mov eax,addr\n"
//     "mov ecx,size\n"
        "mov BL,0x83\n"
        "mov BH,0x00\n"
        "next_byte_calc_summ:\n"
        "xor BH,BYTE PTR [EAX]\n"
        "inc EAX\n"
        "loop next_byte_calc_summ\n"
        "cmp BH,BL\n"
        "jz %l[checksum_is_correct]\n"
        :
        :"a" (addr), "c" (size)
        :
        :checksum_is_correct
    );
    std::cout<<"Контрольная сумма искажена";
    checksum_is_correct:

    asm goto (

    "mov ax, ss\n\t"              // Сохраняем SS в AX (16-битный режим)
    "mov ss, ax\n\t"              // Восстанавливаем SS (блокировка прерываний)
    "pushfq\n\t"                  // Сохраняем RFLAGS (64-битный EFLAGS)
    "pop rax\n\t"                 // Загружаем RFLAGS в RAX
    "test eax, 0x100\n\t"        // Проверяем TF (8-й бит)
    "jz %l[no_step_trace]\n\t"                  // Если TF=0, пропускаем
    :           // Выход: запись в перенную
    :                            // Входы: нет
    :           // Изменяемые регистры и память
    :no_step_trace
);
printf("Step-Trace is detected");
no_step_trace:
 //   int hash_pass=password_to_hash(password);
//    int true_pass=52886;
    if(obfus_cmp(true_pass,hash_pass)){
    return true;
    }else{
        return false;
    }
}

unsigned long GetAddrantiStepTraceCMP_and_CheckIntegrity(){
    bool (*func_ptr)(int,int) = antiStepTraceCMP_and_CheckIntegrity;
    uintptr_t addr = (uintptr_t)func_ptr;
   // std::cout<<(unsigned long)addr;
    unsigned long int_addr=(unsigned long) addr + 66; //66 offset от функции
    return int_addr;
}

std::vector<std::function<int(const std::string&)>> generate_func_arr(int rand1){
int (*func_ptr)(const std::string&) = password_to_hash;
    std::vector<std::function<int(const std::string&)>> arr_func;
    for (int i=0;i<rand1;i++){
        arr_func.push_back(password_to_hash);
    }
    return arr_func;
}
void cpuidCheckVM(uint32_t eax, uint32_t ecx, uint32_t* abcd) {
    __asm__ volatile("cpuid"
        : "=a"(abcd[0]), "=b"(abcd[1]), "=c"(abcd[2]), "=d"(abcd[3])
        : "a"(eax), "c"(ecx));
}

bool isBeingTraced() {
    std::ifstream status_file("/proc/self/status"); // Открываем файл статуса текущего процесса
    std::string line;
    
    while (std::getline(status_file, line)) { // Читаем файл построчно
        if (line.find("TracerPid:") == 0) { // Ищем строку с TracerPid
            int tracer_pid = std::stoi(line.substr(10)); // Извлекаем значение PID
            return tracer_pid != 0; // Если не 0 - процесс находится под отладкой
        }
    }
    return false;
}
bool antiBreakpoint(volatile char* func_addr) {
    //volatile char* ptr = (volatile char*)&antiBreakpoint;
    volatile char* ptr = (volatile char*)&func_addr;
    
    for (int i = 0; i < 100; ++i) {
        if (func_addr[i] == 0xCC) {
            return 1;
        }
    }
    return 0;
}
int main() {
    //int cpustat=GetCPUID(1);
    void (*ext_decrypt)() =decrypt;
 //   ext_decrypt();
asm volatile (                    ///ret=call
        "lea rax, [rip + 1f]\n"   
        "push rax\n"    
        "push %0\n"
        "ret\n"
        "1:\n"
        :          
        : "r" (&decrypt)          
        : "rax", "edi", "memory"  
    );
    //decrypt();
    int cpustat=encryptGetCPUID(1);

    if (isBeingTraced()){
        return 1;
    }
    int family = (cpustat >> 8) & 0xF;
    int ext_model = (cpustat >> 16) & 0xF;
    //std::cout<<"stat "<<family<<" "<<ext_model;
    if (!(obfus_cmp(family,6) && obfus_cmp(ext_model,9))){
        return 0;
    }

     uint32_t abcd[4];
    cpuidCheckVM(0x40000000, 0, abcd);
    char hypervisor_vendor[13] = {0};
    memcpy(hypervisor_vendor, &abcd[1], 4);
    memcpy(hypervisor_vendor + 4, &abcd[2], 4);
    memcpy(hypervisor_vendor + 8, &abcd[3], 4);
    
    if (strcmp(hypervisor_vendor, "KVMKVMKVM") == 0 ||
        strcmp(hypervisor_vendor, "VMwareVMware") == 0 ||
        strcmp(hypervisor_vendor, "Microsoft Hv") == 0 ||
        strcmp(hypervisor_vendor, "XenVMMXenVMM") == 0 ||
        strcmp(hypervisor_vendor, "prl hyperv") == 0 ||  
        strcmp(hypervisor_vendor, "VBoxVBoxVBox") == 0) {
        return 1;  
    }

  uint32_t abcd2[4];
    cpuidCheckVM(1, 0, abcd2);
    if (abcd2[2] & (1 << 31)) {
        return 1;  // Hypervisor 
    }

    std::string login,password;
    std::cout<<"Введите логин ";
    std::cin>>login;
    std::cout<<"Введите пароль ";
    std::cin>>password;


    
    srand(time(nullptr));
    int rand1 = rand()%255;
    std::vector<std::function<int(const std::string&)>> vec_func=generate_func_arr(rand1);
    int rand2 = rand()%rand1;
    int hash_pass=vec_func[rand2](password);
    int true_pass=52886;
    
        asm volatile (
        "xor eax,eax\n"  /////////////jz jmp
        "jz tag\n"
        "jmp 0x7fecdab\n"
        "tag:\n"    
        "jnz inside_mov + 1\n\t" //////////jz jnz
        "jz inside_mov + 1\n\t"
        "inside_mov:\n\t"
        "mov eax, 0x12345678\n\t"   // B8 78 56 34 12
        "xor eax, eax\n\t"
        "mov eax, 1\n\t"
        "nop\n\t"
        :
        :
        : "eax"                    
    );
    long long t1 = GetTickCountLinux();
    if(antiStepTraceCMP_and_CheckIntegrity(true_pass,hash_pass)){
        printf("password correct");
    }else{
        printf("password error");
    }  
	long long t2 = GetTickCountLinux();
	long long t = t2 - t1;
	if (t > 1000)	// больше 1 сек, т.е. по шагам
	{
		printf("debug");
	}
	else	
	{
		printf("no debug");
	}
    
    return 0;
}


//Случаный вызов функции
//jmp  в серединк
//Строка гипервизора
//Бит гипервизора
//Проверка /proc/self/status
// jnz jz
//Инструкции перехода с постоянным условием
//ret=call