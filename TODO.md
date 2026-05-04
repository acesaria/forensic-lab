## TODO LIST

1. Review VM Life cycle (create, shutdown, turn on, destroy)
2. Review init + sudo handling (how to ensure permission correct? rerun sudo -v?
3. Review cli.py => in distro-setup really needed? Can't do auto when run? Same for init command? Simplify!!!
4. Why debian so long creating? How to check what is slowing?
5. Remove profile from build_isf... check and review
6. handle "reason".. not always clear
7. error handling.. and make output clear (Why libvirt error are showed? ecc..) => [Ex. libvirt: QEMU Driver error : Domain not found: no domain with matching name 'build-isf-debian-13']
8. manifest should include virtual (real) disk size
9. separation of concerns not so  clear.. orchestrator.py imports vmmanger and provider at the same time.. avoidable?
10. is SSH wait every time needed? can't reduce polling?