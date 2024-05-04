public class EscenariosPrueba {
    public static void main(String[] args) throws Exception {
        
        System.out.println("Escenario 1: 4 clientes delegados");
        ejecutarEscenario(4);

        
        System.out.println("Escenario 2: 16 clientes delegados");
        ejecutarEscenario(16);

        
        System.out.println("Escenario 3: 32 clientes delegados");
        ejecutarEscenario(32);
    }

    private static void ejecutarEscenario(int numClientes) throws Exception {
        Cliente[] clientes = new Cliente[numClientes];
        Thread[] threads = new Thread[numClientes];

    
        for (int i = 0; i < numClientes; i++) {
            clientes[i] = new Cliente();
            clientes[i].startConnection("127.0.0.1", 6666);
            threads[i] = new Thread(clientes[i]);
            threads[i].start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        System.out.println("Escenario finalizado.");
    }
}