# 🔍 Gradle Dependency Tracer Tool

This Python tool helps trace the full dependency chain for any given dependency (`group:name:version`) from a Gradle build report in JSON format.

It identifies:
- All configurations where the dependency appears
- All unique paths (chains) in the dependency tree leading to that dependency
- Outputs the result to a JSON file (`result.json`)
- Uses object-oriented design for better modularity and readability

---

## 📦 Features

- ✅ Input: JSON file (like `igor-web.json`) exported from Gradle
- ✅ Output: JSON file showing dependency chains and configurations
- ✅ CLI interface to trace any dependency interactively
- ✅ Prints each dependency path in a tree format
- ✅ Object-oriented structure for easy extension

---

## 🧠 How It Works

The tool has the following main classes:

| Class | Responsibility |
|-------|----------------|
| `DependencyPathFinder` | Recursively searches all paths in the dependency tree that lead to the target dependency |
| `DependencyTreeBuilder` | Builds a minimal JSON tree from a list of dependency nodes |
| `GradleDependencyTracer` | Orchestrates loading data, searching dependencies, printing output, and saving results |

---

## 📁 File Structure

.
├── parse_gradle.py # Main script (OOP version)
├── igor-web.json # Input dependency tree (Gradle JSON report)
└── result.json # Output file (overwritten each time)
