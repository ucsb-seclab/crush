import subprocess

from crush import globals


def cast_row(row: str, types: tuple, sep='|'):
    """
    # Example usage
    row = "42, 3.14, Hello"
    types = (int, float, str)

    result = cast_row(row, types)
    print(result)  # Output: [42, 3.14, 'Hello']
    """
    # Split the input string
    row_values = row.split(sep)

    # Check if the number of values in the row matches the number of types provided
    if len(row_values) != len(types):
        raise ValueError("Number of values in the row does not match the number of types provided.")

    # Cast each value to the corresponding type and store it in a new list
    casted_values = [t(value.strip()) for value, t in zip(row_values, types)]

    return tuple(casted_values)


def run_query(query, connection_url=globals.DB_URL, types=(str,)):
    # Run the psql command using subprocess
    result = subprocess.run( # "--variable='FETCH_COUNT=10000'"
        ["psql", connection_url, "--variable", "FETCH_COUNT=10000", "-t", "-A", "-c", query],
        capture_output=True,
        text=True,
        check=True,
    )

    # Split the output by newlines, remove empty lines, and create a list
    rows = [line.strip() for line in result.stdout.split("\n") if line.strip()]

    return [cast_row(row, types) for row in rows]