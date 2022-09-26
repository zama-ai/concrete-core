"""
benchmark_parser
----------------

Parse benchmark results issued by criterion.
"""
import argparse
import pathlib
import json


parser = argparse.ArgumentParser()
parser.add_argument('output-file', help='File storing parsed results')
parser.add_argument('-d', '--results-directory',
                    dest='results_dir', default="target/criterion",
                    help='Location of raw benchmark results')
parser.add_argument('-n', '--series-name', dest='series_name',
                    default="concrete_core_benchmark_timing",
                    help='Name of the data series (as stored in Prometheus)')
parser.add_argument('-e', '--series-help', dest='series_help',
                    default="Timings of crypto operator with various parameters.",
                    help='Description of the data series (as stored in Prometheus)')
parser.add_argument('-t', '--series-tags', dest='series_tags',
                    type=json.loads, default={},
                    help='Tags to apply to all the points in the data series')


def parse_results(results_directory):
    """
    Parse criterion results.

    :param results_directory: Directory where criterion results are stored as :class:`pathlib.Path`

    :return: :class:`list` of data points
    """
    excluded_directories = ["child_generate", "fork", "parent_generate", "report"]
    result_values = list()
    for directory in results_directory.iterdir():
        if directory.name in excluded_directories or not directory.is_dir():
            continue
        for subdir in directory.iterdir():
            if subdir.name == "report":
                continue
            results_dir = subdir.joinpath("new")
            tags = parse_benchmark_file(results_dir)
            for timing in parse_estimate_file(results_dir):
                data_point = dict()
                data_point["value"] = timing.pop("value")
                timing.update(tags)
                data_point["tags"] = tags
                result_values.append(data_point)

    return result_values


def dump_results(results, output_file, series_name,
                 series_help="", series_tags=None):
    """
    Dump parsed results formatted as JSON to file.

    :param results: :class:`list` of data points
    :param output_file: filename for dump file as :class:`pathlib.Path`
    :param series_name: name of the data series as :class:`str`
    :param series_help: description of the data series as :class:`str`
    :param series_tags: constant tags for the series
    """
    output_file.parent().mkdir(parents=True)
    series = [
        {"series_name": series_name,
         "series_help": series_help,
         "series_tags": series_tags or dict(),
         "points": results},
    ]
    output_file.write_text(json.dumps(series))


def parse_benchmark_file(directory):
    """
    Parse file containing details of the parameters used for a benchmark.

    :param directory: directory where a benchmark case results are located as :class:`pathlib.Path`

    :return: :class:`dict` of tags to apply to a data point
    """
    raw_results = _parse_file_to_json(directory, "benchmark.json")
    tags = dict()
    operator, _, raw_config = raw_results["group_id"].partition("Fixture")
    tags["operator"] = operator

    parsed_config = raw_config.strip('<>').split(", ")
    tags["precision"] = parsed_config[0].lstrip("Precision")
    tags["engine"] = parsed_config[1]
    # There is an unneeded parenthesis at the end of the data flavor in concrete-core.
    tags["data_flavor"] = parsed_config[2].strip(")")

    tags["parameters"] = raw_results["value_str"].lstrip(operator + "Parameters ")
    return tags


def parse_estimate_file(directory):
    """
    Parse file containing timing results for a benchmark.

    :param directory: directory where a benchmark case results are located as :class:`pathlib.Path`

    :return: :class:`list` of timings
    """
    raw_results = _parse_file_to_json(directory, "estimates.json")
    timings = list()
    for stat_name in ("mean", "median", "std_dev"):
        if raw_results[stat_name] is None:
            # Slope might not be filled.
            continue

        timings.append(
            {"value": raw_results[stat_name]["point_estimate"],
             "stat": stat_name}
        )

    return timings


def _parse_file_to_json(directory, filename):
    result_file = directory.joinpath(filename)
    return json.loads(result_file.read_text())


if __name__ == "__main__":
    args = parser.parse_args()

    print("Parsing benchmark results...")
    dump_results(parse_results(pathlib.Path(args.results_dir)),
                 pathlib.Path(args.output_file), args.series_name,
                 series_help=args.series_help, series_tags=args.series_tags)

    print("Results parsed.")
