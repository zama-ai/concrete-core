import math
import numpy as np
from matplotlib import pyplot as plt
from scipy.optimize import curve_fit
from sklearn.ensemble import IsolationForest
from sklearn.metrics import mean_tweedie_deviance
from termcolor import colored

from utils import var_to_bit


# Log Extraction

def params_to_string(params):
    return f"N = 2^{int(math.log2(params[0]))} ; k = {int(params[1])} ; level = {int(params[2])} ; baselog = {int(params[3])}"


def extract_parameter(line):
    # line : polynomial_size, glwe_dimension, decomposition_level_count, decomposition_base_log,
    # input_variance, output_variance, predicted_variance
    try:
        return [float(x) for x in line.split(",")[:4]]
    except IndexError:
        return None
    except ValueError:
        return None


def extract_input_variance(line):
    # line : polynomial_size, glwe_dimension, decomposition_level_count, decomposition_base_log,
    # input_variance, output_variance, predicted_variance
    try:
        # return 2. ** (128 + 2 * float(line.split(",")[5]))
        return float(line.split(",")[4])

    except IndexError:
        return None


def extract_exp_output_variance(line):
    # line : polynomial_size, glwe_dimension, decomposition_level_count, decomposition_base_log,
    # input_variance, output_variance, predicted_variance
    try:
        # return 2. ** (128 + 2 * float(line.split(",")[5]))
        return float(line.split(",")[5])

    except IndexError:
        return None


def extract_th_output_variance(line):
    # line : polynomial_size, glwe_dimension, decomposition_level_count, decomposition_base_log,
    # input_variance, output_variance, predicted_variance
    try:
        # return 2. ** (128 + 2 * float(line.split(",")[6]))
        return float(line.split(",")[6])

    except IndexError:
        return None


def extract_from_acquisitions(filename):
    with open(filename, "r") as f:
        res = f.read()

    res = res.split("\n")
    parameters = []
    exp_output_variance = []
    th_output_variance = []
    input_variance = []
    for line in res:
        params = extract_parameter(line)
        exp_output_var = extract_exp_output_variance(line)
        th_output_var = extract_th_output_variance(line)
        input_var = extract_input_variance(line)

        if not (
                params is None or exp_output_var is None or th_output_var is None or input_var is None):
            if exp_output_var < 0.083:
                # * 2**128 to convert the torus variance into a modular variance
                params.append(th_output_var * 2 ** 128)
                parameters.append(params)
                exp_output_variance.append(exp_output_var * 2 ** 128)
                th_output_variance.append(th_output_var * 2 ** 128)
                input_variance.append(input_var * 2 ** 128)
    print(f"There is {len(parameters)} samples ...")
    return np.array(parameters), np.array(exp_output_variance), np.array(
        th_output_variance), np.array(input_variance)


def get_input(new_decomp=False):
    if new_decomp:
        filename = "new_decomp_all_acquisitions.txt"
    else:
        filename = "previous_decomp_all_acquisitions.txt"
    parameters, exp_output_variance, th_output_variance, input_variance = extract_from_acquisitions(
        filename)
    y_values = np.maximum(0.,
                          (exp_output_variance - input_variance))
    x_values = parameters
    return x_values, y_values


def get_input_without_outlier(new_decomp=False):
    x_values, y_values = get_input(new_decomp)
    return remove_outlier(x_values, y_values)


def remove_outlier(x_values, y_values):
    # identify outliers in the training dataset
    iso = IsolationForest(contamination=0.1)
    yhat = iso.fit_predict(x_values)

    # select all rows that are not outliers
    mask = yhat != -1
    previous_size = len(x_values)
    x_values, y_values = x_values[mask, :], y_values[mask]
    new_size = len(x_values)
    print(f"Removing {previous_size - new_size} outliers ...")
    return x_values, y_values


# Noise formula for FFTW

def fft_noise(x, a, d):
    N = x[:, 0]
    k = x[:, 1]
    level = x[:, 2]
    logbase = x[:, 3]
    theoretical_var = x[:, 4]
    return 2 ** a * 2 ** 22 * level * 2. ** (2 * logbase) * N ** d + theoretical_var


def log_fft_noise(x, a, d):
    return np.log2(fft_noise(x, a, d))


def fitting(x_values, y_values):
    popt, pcov = curve_fit(log_fft_noise, x_values, np.log2(y_values))
    return popt


def train(x_values, y_values):
    weights = fitting(x_values, y_values)
    return weights


def test(x_values, y_values, weights):
    mse = 0.
    mse_without_correction = 0.
    for index in range(len(x_values)):
        params = np.array([x_values[index, :]])
        real_out = y_values[index]
        pred_out = max(fft_noise(params, *list(weights))[0], 0.000001)
        mse += (var_to_bit(real_out) - var_to_bit(pred_out)) ** 2
        mse_without_correction += (var_to_bit(real_out) - var_to_bit(params[0, 4])) ** 2
    mse /= len(x_values)
    mse_without_correction /= len(x_values)
    return mse, mse_without_correction


def launch(new_decomp=False):
    x_values, y_values = get_input_without_outlier(new_decomp)
    weights = train(x_values, y_values)
    test(x_values, y_values, weights)
    return weights


def compare_with_previous_formula(new_decomp=False):
    print(
        f"\t\t{colored('Comparing new and old formula', attrs=['bold', 'underline'], color='green')}\n")
    # computing new weights
    x_values, y_values = get_input_without_outlier(new_decomp)
    weights = train(x_values, y_values)
    print(f"\t{colored('New formula', attrs=['bold', 'underline'], color='red')}\n")
    mse, mse_without_correction = test(x_values, y_values, weights)
    print(f"-> weights = {weights}")
    print(f"-> mse = {mse}")
    print(f"-> mse wo correction = {mse_without_correction}\n")

    print(f"\t{colored('Old formula', attrs=['bold', 'underline'], color='red')}\n")

    # testing old weights
    previous_weights = (math.log2(0.016089458900501813), 2.188930746713708)
    mse, mse_without_correction = test(x_values, y_values, previous_weights)
    print(f"-> weights = {previous_weights}")
    print(f"-> mse = {mse}")
    print(f"-> mse wo correction = {mse_without_correction}\n")


def compare_decomposition():
    print(
        f"\t\t{colored('Comparing new and old decomposition', attrs=['bold', 'underline'], color='green')}\n")

    x_values, previous_decomp_y_values = get_input_without_outlier(False)
    x_value_bis, new_decomp_y_values = get_input_without_outlier(True)
    x_values = x_values[:, :4]
    x_value_bis = x_value_bis[:, :4]

    previous_decom = {}
    for x, y in zip(x_values, previous_decomp_y_values):
        previous_decom[tuple(x)] = y

    new_decom = {}
    for x, y in zip(x_value_bis, new_decomp_y_values):
        new_decom[tuple(x)] = y

    diffs = {}
    # print(new_decom.keys())
    for key in previous_decom.keys():
        if key in new_decom.keys():
            if previous_decom[key] != new_decom[key]:
                diffs[key] = 0.5 * math.log2(previous_decom[key]) - 0.5 * math.log2(new_decom[key])
            # else:
            #     diffs[key] = 0.
            # diffs[key] = 0.5 * math.log2(previous_decom[key] - new_decom[key])
        else:
            print(f"Cannot find key {key} in new_decomp ... ")

    diff = np.array(list(diffs.values()))
    print(f"> Computing diff = log(previous_decomp_stddev) - log(new_decomp_stddev) ")
    print(f"> diff mean  = {np.mean(diff)}")
    print(f"> diff median  = {np.median(diff)}")

    plt.figure()
    plt.title("$\log_2(\sigma_{old}) - \log_2(\sigma_{new})$")
    plt.hist(diff, bins=1000, density=True)
    plt.tight_layout()
    # plt.scatter(range(len(diff)), diff)
    plt.show()


if __name__ == "__main__":
    compare_decomposition()
    # compare_with_previous_formula(False)
    # compare_with_previous_formula(True)
