using System;

public class Sample
{
    public static int Add(int a, int b)
    {
        int sum = a + b;
        return sum;
    }

    public static void Main()
    {
        int result = Add(2, 3);
        Console.WriteLine(result);
    }
}
