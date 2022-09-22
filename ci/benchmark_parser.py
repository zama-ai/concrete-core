import argparse
import pathlib
import json

RESULTS_DIRECTORY = "target/criterion"
EXCLUDED_DIRECTORIES = ["child_generate", "fork", "parent_generate", "report"]

parser = argparse.ArgumentParser()
parser.add_argument('output-file', help='File storing parsed results')
parser.add_argument('-d', '--results-directory',
                    dest='results_dir', default=RESULTS_DIRECTORY,
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


def parse_results():
    result_values = list()
    for directory in RESULTS_DIRECTORY.iterdir():
        if directory.name in EXCLUDED_DIRECTORIES or not(directory.is_dir()):
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


def dump_results(results, target_directory, filename, series_name,
                 series_help="", series_tags=None):
    dump_file = target_directory.joinpath(filename)
    series = [
        {"series_name": series_name,
         "series_help": series_help,
         "series_tags": series_tags or dict(),
         "points": results},
    ]
    dump_file.write_text(json.dumps(series))


def parse_benchmark_file(directory):
    raw_results = _parse_file_to_json(directory, "benchmark.json")
    tags = dict()
    operator, _, raw_config = raw_results["group_id"].partition("Fixture")
    tags["operator"] = operator

    parsed_config = raw_config.strip('<>').split(", ")
    tags["precision"] = parsed_config[0].lstrip("Precision")
    tags["engine"] = parsed_config[1]
    tags["data_flavor"] = parsed_config[2].strip(")")  # FIXME There is an unneeded parenthesis at the end of the data flavor in concrete-core

    tags["parameters"] = raw_results["value_str"].lstrip(operator + "Parameters ")
    return tags


def parse_estimate_file(directory):
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
    dump_results(parse_results(), pathlib.Path(args.results_dir),
                 args.output_file, args.series_name,
                 series_help=args.series_help, series_tags=args.series_tags)

    print("Results parsed.")
