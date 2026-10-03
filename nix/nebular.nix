# RS9 candidate boundary: native runtime packaging has not passed qualification.
# This definition cannot instantiate a publishable package.
{ lib, stdenvNoCC, fetchurl, buildFHSEnv ? null, python3 ? null }:
{ product }:
throw "RS9 Nebular candidate withheld: authenticated payload manifest, packaged materializer, full per-system FHS closure and native release smoke are required"
