using System;

public class Sample2
{
    public static void CountUp(int n)
    {
        for (int i = 0; i < n; i++)
        {
            Console.WriteLine("counting: " + i);
        }
    }

    public static void Main()
    {
        CountUp(5);
    }
}
