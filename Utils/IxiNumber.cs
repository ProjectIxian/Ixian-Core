using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace DLT
{
    // An object representing an amount of IXI coins, complete with decimal support. Can handle very large amounts.
    public class IxiNumber
    {
        // A divisor corresponding to 8 decimals as per WhitePaper
        private static BigInteger divisor = BigInteger.Parse("100000000");
        private static int num_decimals = 8;

        // Set the initial value to 0
        BigInteger amount = BigInteger.Zero;

        public IxiNumber()
        {
            amount = BigInteger.Zero;
        }

        public IxiNumber(BigInteger big_integer)
        {
            amount = big_integer;
        }

        public IxiNumber(ulong number)
        {
            amount = new BigInteger(number);
        }

        public IxiNumber(string number)
        {
            string[] split = number.Split('.');
            if (split.Count() > 1 && split[1].Length > 0)
            {
                string second_part = split[1];
                // Check if there are more decimals than neccessary and ignore the rest 
                if(second_part.Length > num_decimals)
                    second_part = second_part.Substring(0, num_decimals);

                BigInteger p1 = BigInteger.Parse(split[0]);
                BigInteger p2 = BigInteger.Parse(second_part);

                // Check for partial decimals
                int s2_length = second_part.Length;
                double exponent = 0;
                if(s2_length < num_decimals)
                    exponent = num_decimals - s2_length;

                double multiplier = 1;
                if(exponent > 0)
                    multiplier = Math.Pow(10, exponent);

                // Multiply the second part if neccessary
                p2 = BigInteger.Multiply(p2, new BigInteger(multiplier));

                // Multiply the first part to make room for the decimals
                p1 = BigInteger.Multiply(p1, divisor);

                // Finally, add both parts
                amount = BigInteger.Add(p1, p2);
            }
            else
            {
                try
                {
                    amount = BigInteger.Parse(number);
                }
                catch(Exception)
                {
                    amount = 0;
                }
                // No decimals detected, multiply the amount 
                amount = BigInteger.Multiply(amount, divisor);

            }
        }

        // Returns a string containing the raw amount
        public string ToRawString()
        {
            return amount.ToString("D");
        }

        // Returns a formatted string containing decimals
        public override string ToString()
        {
            string ret = "ERR";
            try
            {
                BigInteger p1 = BigInteger.Divide(amount, divisor);
                BigInteger p2 = BigInteger.Remainder(amount, divisor);
                string second_part = p2.ToString("D");

                // Check for and add leading 0s
                int s2_length = second_part.Length;
                int padding = num_decimals - s2_length;
                second_part = second_part.PadLeft(s2_length + padding, '0');

                // Return the correctly formatted number
                ret = string.Format("{0}.{1}", p1.ToString("D"), second_part);
            }
            catch(Exception)
            {
                // TODO: handle formatting errors
            }
            return ret;
        }

        public BigInteger getAmount()
        {
            return amount;
        }

        public void add(IxiNumber num)
        {
            amount = BigInteger.Add(amount, num.getAmount());
        }

        public void substract(IxiNumber num)
        {
            amount = BigInteger.Subtract(amount, num.getAmount());
        }

        public void multiply(IxiNumber num)
        {
            amount = BigInteger.Multiply(amount, num.getAmount());
        }

        public void divide(IxiNumber num)
        {
            amount = BigInteger.Divide(amount, num.getAmount());
        }


        public static IxiNumber add(IxiNumber num1, IxiNumber num2)
        {
            return new IxiNumber(BigInteger.Add(num1.getAmount(), num2.getAmount()));
        }

        public static IxiNumber subtract(IxiNumber num1, IxiNumber num2)
        {
            return new IxiNumber(BigInteger.Subtract(num1.getAmount(), num2.getAmount()));
        }

        public static IxiNumber multiply(IxiNumber num1, IxiNumber num2)
        {
            return new IxiNumber(BigInteger.Multiply(num1.getAmount(), num2.getAmount()));
        }

        public static IxiNumber divide(IxiNumber num1, IxiNumber num2)
        {
            return new IxiNumber(BigInteger.Divide(num1.getAmount(), num2.getAmount()));
        }

        public static IxiNumber divRem(IxiNumber num1, IxiNumber num2, out IxiNumber remainder)
        {
            BigInteger bi_remainder = 0;
            BigInteger bi_quotient = BigInteger.DivRem(num1.getAmount(), num2.getAmount(), out bi_remainder);

            remainder = new IxiNumber(bi_remainder);

            // Multiply the bi_quotient part if neccessary
            double multiplier = Math.Pow(10, num_decimals);
            bi_quotient = BigInteger.Multiply(bi_quotient, new BigInteger(multiplier));

            return new IxiNumber(bi_quotient);
        }


        // TODO: equals, assign, +, -
        // add assign from long

        public static implicit operator IxiNumber(string value)
        {
            return new IxiNumber(value);
        }

        public static implicit operator IxiNumber(ulong value)
        {
            return new IxiNumber(value);
        }

        public static bool operator ==(IxiNumber a, long b)
        {
            bool status = false;
            BigInteger bi = new BigInteger(b);
            if (BigInteger.Compare(a.getAmount(), bi) == 0)
            {
                status = true;
            }
            return status;
        }

        public static bool operator !=(IxiNumber a, long b)
        {
            bool status = false;
            BigInteger bi = new BigInteger(b);
            if (BigInteger.Compare(a.getAmount(), bi) != 0)
            {
                status = true;
            }
            return status;
        }

        public static bool operator >(IxiNumber a, long b)
        {
            bool status = false;
            BigInteger bi = new BigInteger(b);
            if (BigInteger.Compare(a.getAmount(), bi) > 0)
            {
                status = true;
            }
            return status;
        }

        public static bool operator <(IxiNumber a, long b)
        {
            bool status = false;
            BigInteger bi = new BigInteger(b);
            if (BigInteger.Compare(a.getAmount(), bi) < 0)
            {
                status = true;
            }
            return status;
        }

        public static bool operator >(IxiNumber a, IxiNumber b)
        {
            bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) > 0)
            {
                status = true;
            }
            return status;
        }

        public static bool operator <(IxiNumber a, IxiNumber b)
        {
            bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) < 0)
            {
                status = true;
            }
            return status;
        }

        public static IxiNumber operator +(IxiNumber a, IxiNumber b)
        {
            return add(a, b);
        }

        public static IxiNumber operator -(IxiNumber a, IxiNumber b)
        {
            return subtract(a, b);
        }


        public static IxiNumber operator *(IxiNumber a, IxiNumber b)
        {
            return multiply(a, b);
        }

        public static IxiNumber operator /(IxiNumber a, IxiNumber b)
        {
            return divide(a, b);
        }


    }
}
