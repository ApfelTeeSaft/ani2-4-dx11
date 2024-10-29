# ani2-on-dx11

![Project Status](https://img.shields.io/badge/status-WIP-red)

This project is a **port of the original Xbox startup animation source code, codenamed "ani2"**, to DirectX 11. The goal is to bring the original code designed for Xbox hardware into a DirectX 11-compatible environment.

## About

**ani2-on-dx11** directly ports the Xbox source code from the original "ani2" startup animation into a DirectX 11 context. This project utilizes the actual animation code used in the Xbox startup sequence rather than recreating it from scratch.

### ⚠️ Disclaimer

I'm not experienced with porting from Xbox source code, so this project might take time and could face challenges. Due to the complexity, I can’t guarantee that this project will be fully completed or that it will function exactly like the original startup animation.

## Features

- Direct port of Xbox's "ani2" startup animation code to DirectX 11
- Original Xbox rendering logic adapted to run on a modern PC
- **XInput Integration:** The original Xbox input code will be ported to XInput, allowing for interaction with the animation.
- **Noclip Mode:** A planned "noclip" mode will allow users to fly through the animation for a unique perspective.

## Requirements

- Visual Studio 2022
- DirectX 11 SDK
- A Windows environment

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/apfelteesaft/ani2-on-dx11.git
   cd ani2-on-dx11
   ```

2. Open the solution in Visual Studio 2022.

3. Compile and run the project on a DirectX 11-compatible system.

## Contributing

If you have experience with Xbox graphics or DirectX, feel free to submit pull requests or open issues. Help is appreciated as this porting process involves unique challenges for me.