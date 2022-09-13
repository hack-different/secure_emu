import pathlib
import os
import typing
import apple_data
import hashlib


class Core:
    pass


class ImageLoader:
    ROMS: dict[str, pathlib.Path] = {}
    _cores: dict[str, typing.Any] = {}
    _loaded = False

    @staticmethod
    def get_securerom(path: str) -> bytes:
        rom_path = pathlib.Path(os.path.dirname(__file__)).joinpath(path)
        with open(rom_path, mode="rb") as file:
            return file.read()

    @staticmethod
    def get_core(core: int) -> Core:
        pass

    @staticmethod
    def _prepare():
        if ImageLoader._loaded:
            return

        for image_path in pathlib.Path(os.path.join(os.path.dirname(__file__), '../ext/roms/resources/APROM')).glob(
                "*"):
            with open(image_path, 'rb') as f:
                data = f.read()
                ImageLoader.ROMS[hashlib.sha256(data).hexdigest()] = image_path

        ImageLoader._cores = apple_data.load_file('cores')

        ImageLoader._loaded = True

