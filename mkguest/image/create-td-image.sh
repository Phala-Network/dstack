#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_DIR=${SCRIPT_DIR}/build
LOGFILE=${BUILD_DIR}/tdx-guest-setup.log
FORCE_RECREATE=false
OFFICIAL_UBUNTU_IMAGE=${OFFICIAL_UBUNTU_IMAGE:-"https://cloud-images.ubuntu.com/releases/noble/release/"}
CLOUD_IMG=${CLOUD_IMG:-"ubuntu-24.04-server-cloudimg-amd64.img"}
CLOUD_IMG_PATH="${BUILD_DIR}/${CLOUD_IMG}"
GUEST_IMG_PATH=$(realpath "${QCOW_IMAGE_FILENAME}")
TMP_GUEST_IMG_PATH=${BUILD_DIR}/tdx-guest-tmp.qcow2
SIZE=50
GUEST_USER=${GUEST_USER:-"tdx"}
GUEST_PASSWORD=${GUEST_PASSWORD:-"123456"}
GUEST_HOSTNAME=${GUEST_HOSTNAME:-"tdx-guest"}

mkdir -p ${BUILD_DIR}

ok() {
    echo -e "\e[1;32mSUCCESS: $*\e[0;0m"
}

error() {
    echo -e "\e[1;31mERROR: $*\e[0;0m"
    cleanup
    exit 1
}

warn() {
    echo -e "\e[1;33mWARN: $*\e[0;0m"
}

info() {
    echo -e "\e[0;33mINFO: $*\e[0;0m"
}

check_tool() {
    [[ "$(command -v $1)" ]] || { error "$1 is not installed" 1>&2 ; }
}

usage() {
    cat <<EOM
Usage: $(basename "$0") [OPTION]...
  -h                        Show this help
  -f                        Force to recreate the output image
  -n                        Guest host name, default is "tdx-guest"
  -u                        Guest user name, default is "tdx"
  -p                        Guest password, default is "123456"
  -s                        Specify the size of guest image
  -o <output file>          Specify the output file, default is tdx-guest-ubuntu-24.04.qcow2.
                            Please make sure the suffix is qcow2. Due to permission consideration,
                            the output file will be put into /tmp/<output file>.
EOM
}

process_args() {
    while getopts "o:s:n:u:p:r:fch" option; do
        case "$option" in
        o) GUEST_IMG_PATH=$(realpath "$OPTARG") ;;
        s) SIZE=${OPTARG} ;;
        n) GUEST_HOSTNAME=${OPTARG} ;;
        u) GUEST_USER=${OPTARG} ;;
        p) GUEST_PASSWORD=${OPTARG} ;;
        f) FORCE_RECREATE=true ;;
        h)
            usage
            exit 0
            ;;
        *)
            echo "Invalid option '-${OPTARG}'"
            usage
            exit 1
            ;;
        esac
    done

    if [[ "${CLOUD_IMG_PATH}" == "${GUEST_IMG_PATH}" ]]; then
        error "Please specify a different name for guest image via -o"
    fi

    if [[ ${GUEST_IMG_PATH} != *.qcow2 ]]; then
        error "The output file should be qcow2 format with the suffix .qcow2."
    fi
}

download_image() {
    # Get the checksum file first
    if [[ -f ${BUILD_DIR}/"SHA256SUMS" ]]; then
        rm ${BUILD_DIR}/"SHA256SUMS"
    fi

    wget "${OFFICIAL_UBUNTU_IMAGE}/SHA256SUMS" -O ${BUILD_DIR}/"SHA256SUMS"

    while :; do
        # Download the cloud image if not exists
        if [[ ! -f ${CLOUD_IMG_PATH} ]]; then
            wget -O ${CLOUD_IMG_PATH} ${OFFICIAL_UBUNTU_IMAGE}/${CLOUD_IMG}
        fi

        # calculate the checksum
        download_sum=$(sha256sum ${CLOUD_IMG_PATH} | awk '{print $1}')
        found=false
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" == *"$CLOUD_IMG"* ]]; then
                if [[ "${line%% *}" != ${download_sum} ]]; then
                    echo "Invalid download file according to sha256sum, re-download"
                    rm ${CLOUD_IMG_PATH}
                else
                    ok "Verify the checksum for Ubuntu cloud image."
                    return
                fi
                found=true
            fi
        done < ${BUILD_DIR}/"SHA256SUMS"
        if [[ $found != "true" ]]; then
            echo "Invalid SHA256SUM file"
            exit 1
        fi
    done
}

create_guest_image() {
    if [ ${FORCE_RECREATE} = "true" ]; then
        rm -f ${CLOUD_IMG_PATH}
    fi

    download_image

    # this image will need to be customized both by virt-customize and virt-install
    # virt-install will interact with libvirtd and if the latter runs in normal user mode
    # we have to make sure that guest image is writable for normal user
    install -m 0777 ${CLOUD_IMG_PATH} ${TMP_GUEST_IMG_PATH}
    if [ $? -eq 0 ]; then
        ok "Copy the ${CLOUD_IMG} => ${TMP_GUEST_IMG_PATH}"
    else
        error "Failed to copy ${CLOUD_IMG} to ${BUILD_DIR}"
    fi

    resize_guest_image
}

resize_guest_image() {
    qemu-img resize ${TMP_GUEST_IMG_PATH} +${SIZE}G
    virt-customize -a ${TMP_GUEST_IMG_PATH} \
        --run-command 'growpart /dev/sda 1' \
        --run-command 'resize2fs /dev/sda1' \
        --run-command 'systemctl mask pollinate.service'
    if [ $? -eq 0 ]; then
        ok "Resize the guest image to ${SIZE}G"
    else
        error "Failed to resize guest image to ${SIZE}G"
    fi
}

config_cloud_init_cleanup() {
  virsh shutdown tdx-config-cloud-init &> /dev/null
  sleep 1
  virsh destroy tdx-config-cloud-init &> /dev/null
  virsh undefine tdx-config-cloud-init &> /dev/null
}

config_cloud_init() {
    pushd ${SCRIPT_DIR}/cloud-init-data
    [ -e ${BUILD_DIR}/ciiso.iso ] && rm ${BUILD_DIR}/ciiso.iso
    cp user-data.template ${BUILD_DIR}/user-data
    cp meta-data.template ${BUILD_DIR}/meta-data

    # configure the user-data
    cat <<EOT >> ${BUILD_DIR}/user-data

user: $GUEST_USER
password: $GUEST_PASSWORD
chpasswd: { expire: False }
EOT

    # configure the meta-data
    cat <<EOT >> ${BUILD_DIR}/meta-data

local-hostname: $GUEST_HOSTNAME
EOT

    info "Generate configuration for cloud-init..."
    genisoimage -output ${BUILD_DIR}/ciiso.iso -volid cidata -joliet -rock ${BUILD_DIR}/user-data ${BUILD_DIR}/meta-data
    info "Apply cloud-init configuration with virt-install..."
    info "(Check logfile for more details ${LOGFILE})"
    popd

    virt-install --debug --memory 4096 --vcpus 4 --name tdx-config-cloud-init \
        --disk ${TMP_GUEST_IMG_PATH} \
        --disk ${BUILD_DIR}/ciiso.iso,device=cdrom \
        --os-variant ubuntu24.04 \
        --virt-type kvm \
        --graphics none \
        --import \
        --wait=12 &>> ${LOGFILE}
    if [ $? -eq 0 ]; then
        ok "Apply cloud-init configuration with virt-install"
        sleep 1
    else
        warn "Please increase wait time(--wait=12) above and try again..."
        error "Failed to configure cloud init. Please check logfile \"${LOGFILE}\" for more information."
    fi

    config_cloud_init_cleanup
}

install_tools() {
    info "Installing tools"
    virt-customize -a ${TMP_GUEST_IMG_PATH} \
       --mkdir /tmp/tdx \
       --copy-in ${SCRIPT_DIR}/tdxctl:/sbin/ \
       --copy-in ${SCRIPT_DIR}/app-compose.service:/etc/systemd/system/ \
       --copy-in ${SCRIPT_DIR}/setup-guest.sh:/tmp/tdx/ \
       --run-command "chmod +x /tmp/tdx/setup-guest.sh" \
       --run-command "/tmp/tdx/setup-guest.sh"

    if [ $? -eq 0 ]; then
        ok "Install tools"
    else
        error "Failed to install tools"
    fi
}

cleanup() {
    if [[ -f ${SCRIPT_DIR}/"SHA256SUMS" ]]; then
        rm ${SCRIPT_DIR}/"SHA256SUMS"
    fi
    info "Cleanup!"
}

echo "=== tdx guest image generation === " > ${LOGFILE}

# sanity cleanup
config_cloud_init_cleanup

check_tool qemu-img
check_tool virt-customize
check_tool virt-install
check_tool genisoimage

info "Installation of required tools"

process_args "$@"

create_guest_image

config_cloud_init

install_tools

cleanup

mv ${TMP_GUEST_IMG_PATH} ${GUEST_IMG_PATH}
chmod a+rw ${GUEST_IMG_PATH}

ok "TDX guest image : ${GUEST_IMG_PATH}"
