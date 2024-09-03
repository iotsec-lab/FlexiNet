# FlexiNet

**FlexiNet** is a lightweight network traffic fingerprinting method optimized for resource-constrained environments. By leveraging Genetic Algorithms (GA) for multi-objective tuning of machine learning models, FlexiNet achieves a balance between accuracy and computational overhead, making it suitable for environments with limited resources.

## Dataset

The dataset used in this project can be accessed [here](https://tinyurl.com/flexinet-dataset). Detailed instructions on how the dataset was generated, including feature extraction methods, are provided in the linked documentation.

## Workflow

### 1. Feature Extraction
The `feature_extraction/main.py` script converts `.pcap` files into `.csv` files, extracting 23 key features from each packet. These features are crucial for the subsequent machine learning tasks. For more details on the feature extraction process, refer to the [dataset documentation](https://tinyurl.com/flexinet-dataset).

### 2. Train and Test Model
The `lite-ML/mlp/run.py` script is used to train the machine learning model with various hyperparameters, as discussed in the FlexiNet paper. This script calculates and outputs all relevant performance metrics, allowing you to evaluate the effectiveness of the model.

### 3. Calculate Resource Utilization
To assess the efficiency of the trained models, the `lite-ML/feature_ext/runner.py` script calculates inference time, memory usage, and CPU utilization for each model trained in the previous step.

### 4. Generate Performance-Related CSV
After completing the training and resource utilization steps, performance metrics such as accuracy, runtime, and memory usage are compiled into a `.csv` file. An example of the output can be found at `evolutionary_algorithm/real_data/ORIN.csv`.

### 5. Genetic Algorithm Optimization
For multi-objective optimization, the `evolutionary_algorithm/genetic_algorithm/run_mlp.py` script employs a Genetic Algorithm to fine-tune the model's hyperparameters. The results of this optimization process are stored in `evolutionary_algorithm/genetic_algorithm/gen_ORIN.csv`.

### 6. Simple Heuristic Algorithm Optimization
For multi-objective optimization, the `evolutionary_algorithm/heuristic/ILS_2.py` script employs a simple Heuristic Algorithm to fine-tune the model's hyperparameters.

