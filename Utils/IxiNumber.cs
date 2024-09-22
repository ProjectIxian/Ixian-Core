// Copyright (C) 2017-2020 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using IXICore.Meta;
using System;
using System.Linq;
using System.Numerics;

namespace IXICore
{
    // An object representing an amount of IXI coins, complete with decimal support. Can handle very large amounts.
    public class IxiNumber : IComparable<IxiNumber>
    {
        // A divisor corresponding to 8 decimals as per WhitePaper
        private static BigInteger divisor = 100000000;
        private static int num_decimals = 8;

        // Set the initial value to 0
        public BigInteger amount { get; private set; } = BigInteger.Zero;

        public IxiNumber()
        {
            amount = BigInteger.Zero;
        }

        public IxiNumber(IxiNumber src)
        {
            amount = new BigInteger(src.amount.ToByteArray());
        }

        public IxiNumber(BigInteger big_integer)
        {
            amount = big_integer;
        }

        public IxiNumber(byte[] bytes)
        {
            amount = new BigInteger(bytes);
        }

        public IxiNumber(ulong number)
        {
            amount = BigInteger.Multiply(number, divisor);
        }

        public IxiNumber(long number)
        {
            amount = BigInteger.Multiply(number, divisor);
        }

        public IxiNumber(int number)
        {
            amount = BigInteger.Multiply(number, divisor);
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

                BigInteger p1 = 0;
                BigInteger p2 = 0;

                // Could be cleaned up with tryParse
                try
                {
                    p1 = BigInteger.Parse(split[0]);
                }
                catch (Exception)
                {
                    p1 = 0;
                }

                try
                {
                    p2 = BigInteger.Parse(second_part);
                }
                catch (Exception)
                {
                    p2 = 0;
                }

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
                BigInteger p2;
                BigInteger p1 = BigInteger.DivRem(amount, divisor, out p2);
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

        public override int GetHashCode()
        {
            return amount.GetHashCode();
        }

        public override bool Equals(object obj)
        {
            if (obj is IxiNumber)
            {
                return this == (IxiNumber)obj;
            }
            if(obj is long)
            {
                return this == (long)obj;
            }
            return false;
        }

        public BigInteger getAmount()
        {
            return amount;
        }

        public byte[] getBytes()
        {
            return amount.ToByteArray();
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
            amount = BigInteger.Divide(BigInteger.Multiply(amount, num.getAmount()), divisor);
        }

        public void divide(IxiNumber num)
        {
            amount = BigInteger.Divide(BigInteger.Multiply(amount, divisor), num.getAmount());
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
            return new IxiNumber(BigInteger.Divide(BigInteger.Multiply(num1.getAmount(), num2.getAmount()), divisor));
        }

        public static IxiNumber divide(IxiNumber num1, IxiNumber num2)
        {
            return new IxiNumber(BigInteger.Divide(BigInteger.Multiply(num1.getAmount(), divisor), num2.getAmount()));
        }
        
        public static IxiNumber divRem(IxiNumber num1, IxiNumber num2, out IxiNumber remainder)
        {
            BigInteger bi_remainder = 0;
            BigInteger bi_quotient = BigInteger.DivRem(BigInteger.Multiply(num1.getAmount(), divisor), num2.getAmount(), out bi_remainder);

            remainder = new IxiNumber(BigInteger.Divide(bi_remainder, divisor));

            return new IxiNumber(bi_quotient);
        }


        // TODO: equals, assign, +, -

        public static implicit operator IxiNumber(string value)
        {
            return new IxiNumber(value);
        }

        public static implicit operator IxiNumber(ulong value)
        {
            return new IxiNumber(value);
        }

        public static implicit operator IxiNumber(long value)
        {
            return new IxiNumber(value);
        }

        public static implicit operator IxiNumber(int value)
        {
            return new IxiNumber(value);
        }
        /*
        public static bool operator ==(IxiNumber a, long b)
        {
            bool status = false;
            BigInteger bi = new BigInteger(b);
            if (BigInteger.Compare(a.getAmount(), bi) == 0)
            {
                status = true;
            }
            return status;
        }*/

        public static bool operator ==(IxiNumber a, IxiNumber b)
        {
            if (a is null && b is null)
            {
                return true;
            }

            if (a is null || b is null)
            {
                return false;
            }

            bool status = false;
            if(BigInteger.Compare(a.getAmount(), b.getAmount()) == 0)
            {
                status = true;
            }
            return status;
        }
        /*
        public static bool operator !=(IxiNumber a, long b)
        {
            bool status = false;
            BigInteger bi = new BigInteger(b);
            if (BigInteger.Compare(a.getAmount(), bi) != 0)
            {
                status = true;
            }
            return status;
        }*/

        public static bool operator !=(IxiNumber a, IxiNumber b)
        {
            return !(a == b);
            /*bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) != 0)
            {
                status = true;
            }
            return status;*/
        }
        /*
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

        public static bool operator >=(IxiNumber a, long b)
        {
            bool status = false;
            BigInteger bi = new BigInteger(b);
            if (BigInteger.Compare(a.getAmount(), bi) >= 0)
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

        public static bool operator <=(IxiNumber a, long b)
        {
            bool status = false;
            BigInteger bi = new BigInteger(b);
            if (BigInteger.Compare(a.getAmount(), bi) <= 0)
            {
                status = true;
            }
            return status;
        }
        */
        public static bool operator >(IxiNumber a, IxiNumber b)
        {
            bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) > 0)
            {
                status = true;
            }
            return status;
        }

        public static bool operator >=(IxiNumber a, IxiNumber b)
        {
            bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) >= 0)
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

        public static bool operator <=(IxiNumber a, IxiNumber b)
        {
            bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) <= 0)
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


        public static void test()
        {
            IxiNumber num1 = new IxiNumber("2.00000000");
            IxiNumber num2 = new IxiNumber("2.0");
            ulong num3 = 2;
            long num4 = 2;
            int num5 = 2;

            Logging.info(num1.ToString());
            Logging.info(num2.ToString());
            Logging.info("div: " + (num1 / num2).ToString());
            Logging.info("mul: " + (num1 * num2).ToString());
            Logging.info("div: " + (num1 / num3).ToString());
            Logging.info("mul: " + (num1 * num3).ToString());
            Logging.info("div: " + (num1 / num4).ToString());
            Logging.info("mul: " + (num1 * num4).ToString());
            Logging.info("div: " + (num1 / num5).ToString());
            Logging.info("mul: " + (num1 * num5).ToString());

            num1 = new IxiNumber("0.5");
            num2 = new IxiNumber("2");

            Logging.info(num1.ToString());
            Logging.info(num2.ToString());
            Logging.info("div: " + (num1 / num2).ToString());
            Logging.info("mul: " + (num1 * num2).ToString());
            Logging.info("div: " + (num1 / num3).ToString());
            Logging.info("mul: " + (num1 * num3).ToString());
            Logging.info("div: " + (num1 / num4).ToString());
            Logging.info("mul: " + (num1 * num4).ToString());
            Logging.info("div: " + (num1 / num5).ToString());
            Logging.info("mul: " + (num1 * num5).ToString());

            num1 = new IxiNumber(2);
            num2 = new IxiNumber(2);

            Logging.info(num1.ToString());
            Logging.info(num2.ToString());
            Logging.info("div: " + (num1 / num2).ToString());
            Logging.info("mul: " + (num1 * num2).ToString());
            Logging.info("div: " + (num1 / num3).ToString());
            Logging.info("mul: " + (num1 * num3).ToString());
            Logging.info("div: " + (num1 / num4).ToString());
            Logging.info("mul: " + (num1 * num4).ToString());
            Logging.info("div: " + (num1 / num5).ToString());
            Logging.info("mul: " + (num1 * num5).ToString());

            num1 = new IxiNumber("1.23456789");
            num2 = new IxiNumber("2.34567890");
            double num1d = 1.23456789;
            double num2d = 2.34567890;

            Logging.info(num1.ToString());
            Logging.info(num2.ToString());
            Logging.info("div: " + (num1 / num2).ToString());
            Logging.info("mul: " + (num1 * num2).ToString());
            Logging.info("div: " + (num1d / num2d).ToString());
            Logging.info("mul: " + (num1d * num2d).ToString());

            num1 = new IxiNumber("1.23456789");
            num2 = new IxiNumber("2");
            num3 = 2;

            Logging.info(num1.ToString());
            Logging.info(num2.ToString());
            Logging.info("div: " + (num1 / num2).ToString());
            Logging.info("mul: " + (num1 * num2).ToString());
            Logging.info("div: " + (num1 / num3).ToString());
            Logging.info("mul: " + (num1 * num3).ToString());
        }

        public int CompareTo(IxiNumber other)
        {
            return getAmount().CompareTo(other.getAmount());
        }
    }
}
