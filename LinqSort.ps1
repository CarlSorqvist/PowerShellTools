$Code = @"
using System;
using System.Collections.Generic;
using System.Linq;

public static class LinqPowerShell
{
    public static IEnumerable<T> Sort<T>(this IEnumerable<T> source)
    {
        return source.Sort(false);
    }
    public static IEnumerable<T> Sort<T>(this IEnumerable<T> source, bool descending)
    {
        return source.Sort(descending, Comparer<T>.Default);
    }
    public static IEnumerable<T> Sort<T>(this IEnumerable<T> source, bool descending, IComparer<T> comparer)
    {
        return descending ? source.OrderByDescending(k => k, comparer) : source.OrderBy(k => k, comparer);
    }
}
"@
Add-Type -TypeDefinition $Code -Language CSharp -ReferencedAssemblies mscorlib, System.Security -ErrorAction Stop

# [LinqPowerShell]::Sort($Array)