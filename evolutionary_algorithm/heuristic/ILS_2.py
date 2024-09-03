import pandas as pd
import csv
import random
from itertools import product
import copy
import numpy as np
import os

global results


data_path = "Normalized_mlp_experiment_data - ORIN-normalized.csv"
selected_cases = set()
weights = {
    'accuracy': 0.25,  # Example weight, adjust based on the importance of accuracy
    'time': 0.25,  # Adjust based on the importance of minimizing time
    'memory': 0.5,  # Adjust based on the importance of minimizing memory usage
}

param_grid = {
    'hidden_layer_sizes': [(50,), (100,), (150,), (50, 50), (50, 100), (50, 150), (100, 50), (100, 100), (100, 150), (150, 50), (150, 100), (150, 150), (50, 50, 50), (50, 50, 100), (50, 50, 150), (50, 100, 50), (50, 100, 100), (50, 100, 150), (50, 150, 50), (50, 150, 100), (50, 150, 150), (100, 50, 50), (100, 50, 100), (100, 50, 150), (100, 100, 50), (100, 100, 100), (100, 100, 150), (100, 150, 50), (100, 150, 100), (100, 150, 150), (150, 50, 50), (150, 50, 100), (150, 50, 150), (150, 100, 50), (150, 100, 100), (150, 100, 150), (150, 150, 50), (150, 150, 100), (150, 150, 150)],
    'activation': ['identity','relu', 'tanh'],
    'solver': ['sgd', 'adam', 'lbfgs'],
    'alpha': [0.01, 0.001, 0.0001],
    'learning_rate': ['constant', 'adaptive', 'invscaling'],
    'warm_start': [True, False]
}

def search_space_init():
    search_dict = {}
    for hidden_layer_sizes, activation, solver, alpha, learning_rate, warm_start in product(*param_grid.values()): # search space initialization
        param_tuple = (hidden_layer_sizes, activation, solver, alpha, learning_rate, warm_start)
        search_dict[param_tuple] = {}
    return search_dict


def load_data():
    search_dict = search_space_init()
    csv_data = pd.read_csv(data_path)
    total_data = len(csv_data)
    max_f1 = -1
    max_memory = -1
    max_inference_time = -1
    for i in range(total_data):
        row = csv_data.iloc[i]
        l1 = row['l1']
        l2 = row['l2']
        l3 = row['l3']
        layers = [l1, l2, l3]
        activation = row['activation']
        solver = row['solver']
        learning_rate = row['learning_rate']
        alpha = row['alpha']
        warm_start = row['warm_start']
        new_layers = []
        for layer in layers:
            if layer > 0:
                new_layers.append(layer)

        new_layers = tuple(new_layers)
        key = (new_layers, activation, solver, alpha, learning_rate, warm_start)
        search_dict[key] = {
            'f1': row['f1'],
            'inference_time': row['Normalized_inference_time'],
            'memory': row['Normalized_total_addr_space'],
            'idx': row['idx']
        }
        max_f1 = max_f1 if max_f1 > row['f1'] else row['f1']
        max_inference_time = max_inference_time if max_inference_time > row['Normalized_inference_time'] else row[
            'Normalized_inference_time']
        max_memory = max_memory if max_memory > row['Normalized_total_addr_space'] else row['Normalized_total_addr_space']

    data = {
        'search_space': search_dict,
        'max': {
            'f1': max_f1,
            'memory': max_memory,
            'inference_time': max_inference_time
        }
    }
    return data


data = load_data()
#print(data)
search_dict = data['search_space']
last_perturbed_param = None


# def generate_neighbor_cases(base_solution, param_grid):
#     all_cases = []
#     # Convert base_solution to a list for easier manipulation
#     base_solution_list = [base_solution[param] for param in base_solution]
#     print(base_solution_list)
#     # Iterate through each parameter in the base solution
#     for i, (param_name, base_value) in enumerate(base_solution.items()):
#         values = param_grid[param_name]
#         #print(base_value)
#         base_index = values.index(base_value)
#         #print(values)
#         #print(base_index)
#
#         # Compute indices for left and right neighbors with circular behavior
#         left_index = (base_index - 1) % len(values)
#         right_index = (base_index + 1) % len(values)
#
#         # Create cases for the left neighbor
#         left_case = base_solution_list.copy()
#         left_case[i] = values[left_index]
#         left_case = tuple([base_solution[param] if param != param_name else values[left_index] for param in base_solution] + [param_name,'left'])
#         #left_case =
#         all_cases.append(tuple(left_case))
#
#         # Create cases for the right neighbor
#         right_case = base_solution_list.copy()
#         right_case[i] = values[right_index]
#         #right_case = right_case.append(param_name)
#         right_case = tuple(
#             [base_solution[param] if param != param_name else values[right_index] for param in base_solution] + [
#                 param_name,'right'])
#         #print(right_case)
#         all_cases.append(tuple(right_case))
#     #print(all_cases)
#     return all_cases

def hash_model(solution, param_grid):
    s = "$"
    #print(solution)
    for param_name, base_value in solution.items():
        values = param_grid[param_name]
        _index = values.index(base_value)
        s += "{}_{}$".format(param_name, _index)
    # print(s)
    return s


def generate_neighbor_cases(base_solution, param_grid, last_models):
    all_cases = []
    # Iterate through each parameter in the base solution
    for param_name, base_value in base_solution.items():
        values = param_grid[param_name]
        base_index = values.index(base_value)

        # Compute indices for left and right neighbors with circular behavior
        left_index = (base_index - 1) % len(values)
        # Create cases for the left neighbor as dictionaries
        left_case = base_solution.copy()
        left_case[param_name] = values[left_index]
        hash_left = hash_model(left_case, param_grid)
        if hash_left in last_models:
            # Compute indices for left and right neighbors with circular behavior
            left_index = (base_index - 2) % len(values)
            # Create cases for the left neighbor as dictionaries
            left_case = base_solution.copy()
            left_case[param_name] = values[left_index]

        right_index = (base_index + 1) % len(values)
        # Create cases for the right neighbor as dictionaries
        right_case = base_solution.copy()
        right_case[param_name] = values[right_index]
        right_hash = hash_model(right_case, param_grid)

        if right_hash in last_models:
            # Compute indices for left and right neighbors with circular behavior
            right_index = (base_index + 2) % len(values)
            # Create cases for the right neighbor as dictionaries
            right_case = base_solution.copy()
            right_case[param_name] = values[right_index]

        # left_case['direction'] = 'left'
        # left_case['changed_param'] = param_name

        # Create cases for the right neighbor as dictionaries
        # right_case = base_solution.copy()
        # right_case[param_name] = values[right_index]
        # right_case['direction'] = 'right'
        # right_case['changed_param'] = param_name

        all_cases.extend([left_case, right_case])
    #print(all_cases)
    # for c in all_cases:
    #     print(hash_model(c, param_grid))
    #print(all_cases)
    return all_cases

def evaluate_score(case, search_dict, weights):
    #case = case[:-2]
    case_key = tuple(case.values())
    if case_key in search_dict:
        #print(case)
        metrics = search_dict[case_key]
        #print(metrics)
        f1 = metrics['f1']
        inference_time = metrics['inference_time']
        memory = metrics['memory']
        idx = metrics['idx']
    else:
        # Handle cases where metrics are not available (e.g., return a default score or raise an error)
        return None

    # Calculate the score using the provided formula
    score = (weights['accuracy'] * f1) - (weights['time'] * inference_time) - (weights['memory'] * memory)
    return score,idx, f1, inference_time, memory


def find_best_case(cases, search_dict, weights, current_solution):
    best_case = None
    highest_score = -float('inf')  # Initialize with the lowest possible score
    #print("here")
    for case in cases:
        #print(case)
        score, idx, f1, inference_time, memory = evaluate_score(case, search_dict, weights)
        #print(score)
        if score is not None and score > highest_score:
            highest_score = score
            best_case = case
    score_base, idx, base_f1, base_inference_time, base_memory = evaluate_score(current_solution, search_dict, weights)
    if score_base > highest_score:
        return current_solution, score_base, idx, base_f1, base_inference_time, base_memory
    else:
    #best_case = np.random.choice(cases)
        return best_case, highest_score, idx, f1, inference_time, memory



def perform_local_search(current_solution, param_grid, weights, search_dict):
    # # Initialize the score of the current solution
    last_models = []

    for i in range(300):
        #print("\n starting model at round {}\n".format(i+1), hash_model(current_solution, param_grid), "\n")

        all_cases = generate_neighbor_cases(current_solution, param_grid, last_models)
        best_case, score, idx, f1, inference_time, memory = find_best_case(all_cases, search_dict, weights, current_solution)
       # last_models= [current_solution]
        last_models = [hash_model(current_solution, param_grid)]
        current_solution = best_case

    print("solution:", current_solution)
    print("Score:", score)
    print("index, f1, time, memory:", idx, f1, inference_time, memory)

    result = {
        'index': idx,
        'weight_accuracy': weights['accuracy'],
        'weight_time': weights['time'],
        'weight_memory': weights['memory'],
        'f1': f1,
        'time': inference_time,
        'memory': memory,
        'hidden_layer_sizes': current_solution['hidden_layer_sizes'],
        'activation': current_solution['activation'],
        'solver': current_solution['solver'],
        'alpha': current_solution['alpha'],
        'learning_rate': current_solution['learning_rate'],
        'warm_start': current_solution['warm_start'],

    }
    results.append(result)

    # After all iterations, save results to Excel
    # df = pd.DataFrame(results)
    # df.to_excel("heuristic_results.xlsx", index=False)


def append_results_to_excel(new_results, file_path='results.xlsx'):
    # Check if the file exists
    if os.path.exists(file_path):
        # Read the existing data
        df_existing = pd.read_excel(file_path)
    else:
        df_existing = pd.DataFrame()

    # Convert new results to DataFrame
    df_new = pd.DataFrame(new_results)

    # Append new results to existing ones
    df_final = pd.concat([df_existing, df_new], ignore_index=True)

    # Save the updated DataFrame back to Excel
    df_final.to_excel(file_path, index=False)



#print("base:", base_solution)
# last_models.append(hash_model(base_solution, param_grid))
results = []

for _ in range(10):
    base_solution = {param: random.choice(values) for param, values in param_grid.items()}
    perform_local_search(base_solution, param_grid, weights, search_dict)
append_results_to_excel(results, 'heuristics_results_3D_new.xlsx')









